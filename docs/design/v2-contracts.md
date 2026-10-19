# Laneboss v2 frozen contracts

Contract revision: **v2.0-draft.4**, consolidated by `lb-v2-integrate`.
This revision is prepared for the supervising independent review; it is not
evidence that those reviews, consumer implementations or runtime gates passed.
Source inspected: `e002f6e` (the
`bdacbe3` architecture plus measured-evidence addenda). This is a contract and
compilable scaffold, not a working isolation implementation or release approval.
The active build brief applies the recommended defaults in
[isolation.md](isolation.md) §11 under R102. R103 requires independent gating
reviews; this executor does not perform or accept its own production review.
Owner decision **R108** supersedes the older judge comparison/promotion text in
that design: self-hosted Clef-flash is the default now. The corpus calibrates
thresholds; neither a Jev comparison nor a two-week shadow period is a promotion
or release prerequisite. TypeSafe Jev remains an explicitly selected alternative.

## 1. Authority, versions and ownership

One Go executable supplies `laneboss serve`, socket clients and restricted
internal worker modes. The dedicated service UID owns all authoritative state.
An agent has no direct management DB, journal, policy, credential-store or
shared-control-socket access. A renamed client has exactly the same peer-derived
authority. Command text is data for explicit organizational blacklist policy;
it is never the file, identity or process protection boundary.

The socket protocol is `laneboss.rpc.v2`, schema integer `2`; event schema is
also `2`. These are independent of the retained historical prompt protocol
`1.3.0` and binary version `0.7.0`. The integration tree's version output labels itself
`v2-incomplete`; packaging chooses the eventual release version. Unsupported
protocol/schema/artifact generations refuse. There is no direct-state fallback,
legacy-open registration, unprotected launch, third production agent driver,
command allowlist, forced worktree removal or automatic paid-provider fallback.

The current executable is deliberately routed to v2. Unfinished calls
return `*api.Error{code:"not_implemented",owner:"lb-v2-…"}` and a nonzero
exit. Common file-backed RPC parsing and composition are implemented; dependencies
remain unfinished, including installed service hosting. It must not be installed
as a working replacement.
The existing `--install-release` entry remains an administrative installer
exception, not an agent state API. Help/version are local metadata. All ordinary
state commands become socket clients. The six `internal` modes are fixed
service/helper jobs authenticated by an installed binding and a single-use
lease; the binary's possession or a mode argument grants nothing.

`internal/v2/api` is a leaf package importing only the standard library. Its
JSON tags, method registry, event registry and interface signatures are frozen
at this revision; §14 records the coordinated changes from draft.2 and §15
lists the draft.3 → draft.4 corrections and affected consumers.
Feature packages import it and implement their own files. They do not import
one another's concrete services. `internal/v2/assembly` alone composes concrete
components. `cmd/laneboss/main.go`, `cli/dispatch.go`, `cli/cli.go`,
`cli/serve.go`, module wiring, Go dependencies and this contract have **one
owner: lb-v2-integrate** after this freeze. Feature lanes must not change them.

Each RPC has a preassigned `cli/commands_<owner>.go` file and typed service
method. Aliases are already in the dispatch table. Internal worker entry files
are similarly split by owner. New feature implementation and tests belong only
to the paths in [v2-lanes.md](v2-lanes.md). A discovered contract defect goes to
the integration owner as a file-backed amendment naming every consumer, wire
compatibility impact and acceptance change. Only that owner applies one
reviewed revision. Do not add a parallel type, guess a field, or quietly change
the meaning of an existing field.

### Package disposition

All paths below are under `internal/` unless specified otherwise. “Keep”
means preserve the useful behavior; it does not permit legacy code to run with
the state owner's authority. Existing packages remain read-only porting inputs
for feature lanes. Only the explicit legacy owners in the lane plan edit them.

| Existing packages | Disposition and v2 destination |
| --- | --- |
| `authorship, cliargs, contextio, guardtime, identity, instancename, jsontext, observation, protocol, runnermodel, textcontext, worktreepath` | Keep pure formatting, validation, protocol bytes and observation logic. Audit side effects before reuse. |
| `cli, bootstrap, config, settings, settingscli, start, brief, doctor, doctorbase, org, orgtree, rolepolicy, plugin, jobcatalog` | Change: thin v2 clients plus `policy, templates, admin, approval`; canonical edits use D6. Templates and policy text remain source assets. |
| `identityd, caller, delegation, ticketcmd, peers` | Port trusted ownership, ticket and provenance checks to `identity, peer/linux, peer/darwin`; delete active open-registration/label authority. Historical readers remain in migration. |
| `eventstore, event, state, storecli, decisions, decisionsrv, ledger, refusal, toolrecord` | Port storage/hash/replay/search semantics to `store, service, records`. No client SQLite, arbitrary server-side DB path or lane-authored lifecycle event. |
| `lane, laneturns, report, disk` | Port to `lifecycle, messaging, watchdog` and confined `dataworker`; preserve scan/review, budgets, mail, archive/read-back and disk-latch semantics. |
| `box, boxaws, boxcfg, boxcore, boxexec, boxgcp, boxguest, boxledger, boxrun` | Preserve provider/fence/cost/collection contracts in confined resource workers through `records` RPC adapters. Cloud capability is a named grant; no host shell/credential inheritance. |
| `judge, typesafe, adapters` | Keep wire validators/fixtures and bounded accounting; change to `judge, judge/typesafe, judge/clef, guidance`. Provider subprocess/network work occurs outside state authority. |
| `dashboard, orgdiscord` | Port views, locale/themes, receipts and channel integrations to `dashboard, messaging`; human authentication moves to `identity`. |
| `installation, claudockcli, cosprocess, selfexec, subreaper` | Keep immutable artifact/companion verification and useful terminal/process primitives; managed execution moves to `distribution, admin, runner/*, lifecycle`. No unconfined agent launch. |
| `hookblacklist, hookconfig, hookpaths` | Keep historical source parsing and exact rule provenance; active hooks become `policy.evaluate`/guidance clients. Legacy patterns cannot remain a second refusal engine. |
| `orghook` | After OS acceptance, delete isolation.md §7's built-in write/boundary/obscured-call prediction engine and its protection-only consumers. Retain blacklist text, Instead routes, historical evidence and small lexical helpers needed for data interpretation. |
| `lanesandbox` | Replace entirely as an active backend with `isolation/linux, isolation/mac`. Delete allow-default/read-unconfined and “continue without sandbox” behavior after replacement evidence. |
| `faults, testenv, testdata` | Keep controlled fault infrastructure and historical fixtures; no production fixture driver or constant pass. Port distinct canaries into `e2e/v2`. |

New packages and their concrete stub interfaces are:

| Package below `internal/v2` | Contract / responsibility | Owner |
| --- | --- | --- |
| `api` | All frozen wire objects, closed method/event catalogs and dependency interfaces | integrate |
| `client, service, store` | Bounded socket transport, authentication gate, durable transactions/outbox and scoped projections | service |
| `identity, peer/linux` | `Authenticator, HumanVerifier, PeerVerifier`; Linux lifetime identity and human confirmation | identity |
| `peer/darwin, isolation/mac` | Native audit-token identity, per-lane UID and deny-default Seatbelt | darwin |
| `isolation/linux` | `Launcher`; bwrap + Landlock + containment/network gate | linux |
| `admin` | `Helper`, administrator installation/probes and restricted helper mode | admin |
| `grants, dataworker` | `GrantResolver, DataWorker`; subset validation and confined copy/Git/test/render/archive workers | grants |
| `secrets, secrets/native` | `CredentialBroker, SecretBackend`; encrypted native store and scoped runtime injection | secrets |
| `runner/claudock, runner/codex` | Separate `Runner` implementations; private histories and selected credential slots | claudock / codex |
| `lifecycle` | Start / adopt / resume / turn / stop / review / archive / clean, capture, events, stream visibility, internal continuation | lifecycle |
| `watchdog` | `Watchdog`; validated quota continuation, cancellation and room/backoff | watchdog |
| `messaging` | D7 routing, mail/turn receipts, report/channel outbox | messaging |
| `policy` | Layered config, judged blacklist, positive-only skip and outage policy | policy |
| `judge, judge/typesafe, judge/clef` | `Judge`; pinned provider adapters and bounded normalized results | judge |
| `guidance` | Per-logical-turn selection, recency ranking and binding context | guidance |
| `templates` | Role/task/grant briefing, source retention, twelve default workflow rules | templates |
| `approval` | D6 staging, exact-diff approval and atomic generation application | approval |
| `dashboard` | Human data API and actions through the same typed service operations | dashboard |
| `records` | Search/decisions/ledger/observations and resource-worker compatibility ports | integrate |
| `migration` | Frozen old-store verification/import, provenance and rollback plan | migration |
| `distribution` | Release verification, coherent upgrade and recovery | packaging |
| `assembly, cli` common files | Composition root and immutable dispatch; feature command files have separate owners | integrate |

## 2. Socket protocol and errors

Use Unix stream sockets with **4-byte unsigned big-endian payload length**
followed by exactly that many UTF-8 JSON bytes. Maximum payload is 1,048,576
bytes, including envelope/base64 expansion. Reject zero length, duplicate keys,
unknown fields, invalid UTF-8, nonfinite numbers, trailing JSON and oversize
frames before any mutation. Do not accept SCM_RIGHTS/ancillary descriptors.
One request is outstanding per connection; event/attach streams use dedicated
connections so a slow watcher cannot block control operations.

The service validates a read-only installed binding at startup and the client
validates it before connecting. It names configuration, endpoint generation,
service UID and the mapped server UID/GID inside a namespace, artifact digest
and compatible protocol/schema. Endpoints are separately ACL-protected for a
lane, human administration and the root helper. A lane endpoint cannot access a
human/helper method even with a stolen label. Only health is public.

The exact envelope is:

```json
{
  "protocol": "laneboss.rpc.v2",
  "schema": 2,
  "config": "example",
  "request_id": "request-opaque-id",
  "idempotency_key": "operation-opaque-key",
  "request_sha256": "<64 lowercase hex digits>",
  "method": "lane.status",
  "params": {"life_id": "life-opaque-id", "run": 1}
}
```

An optional envelope `proof: ProofRef` carries human confirmation. It is not part
of `params`, and lane endpoints reject it. Success has `protocol,schema,request_id,last_seq,result`; failure substitutes
`error` for `result`. Exactly one is present; an error never accompanies a
successful zero object. `Error` fields are `code,message,instead,retryable`,
optional `operation_id,owner`. Diagnostics must not echo arbitrary input,
credential values or complete environment/settings objects.

IDs are opaque service-issued strings, 1–128 ASCII letters/digits/hyphen/underscore
(except client request/idempotency IDs, which require at least 128 random bits).
IDs are not bearer authority. Names are configuration-local. SHA-256 digests
are 64 lowercase hexadecimal characters. Timestamps are RFC3339Nano UTC with
`Z`. JSON integers must be exact, within `0..2^53-1`; signed exit/signal values
use int32 range. Arrays are always arrays, including `[]`, never null.
Where a declared Go schema uses `[N]T`, its JSON array has exactly N elements,
each validated as T. Short or long fixed arrays are refused before unmarshaling;
Go's zero padding and truncation do not define a wire shape.
Required fields must be present even when false/zero/empty is valid. Optional
fields in the schema appendix may be omitted, but must not be explicit null.
An unspecified or unknown enum is invalid, never an implicit permissive default.

`request_sha256 = SHA256(RFC8785-JCS({protocol,schema,config,method,params}))`.
Preserve the original frame and uploaded source bytes separately from that
canonical digest. The idempotency domain is
`(config, authenticated principal/life, method, idempotency_key)`. All requests
carry a key; only mutations reserve durable idempotency records. Same key and
digest returns the original receipt/result, including across crashes; changed
digest returns `idempotency_conflict`. Persist the reservation, events,
projections and outbox intent atomically before any effect. A reply lost after
launch cannot cause a second launch. Read retries reflect current authorized
state. Retain mutation receipts for the life of the configuration/history;
do not expire a key while its effect might still be retried.

Authenticate and recheck current authority before replaying a receipt. Never
leak a formerly authorized result after revocation. Replay is checked before
base-generation comparison and proof consumption, so the identical completed
mutation remains idempotent. New keys with a consumed proof fail. All change
and lifecycle CAS fields compare to the target's current generation; `0` is
valid only where creating an object explicitly calls for an absent base.

| Error code | Meaning / required action | CLI exit |
| --- | --- | --- |
| `invalid_request` | Invalid shape, unknown enum/field or bound exceeded; correct the file input | 2 |
| `unauthenticated, forbidden` | Peer/proof/scope/relationship refusal; use the stated route | 2 |
| `not_found` | Absent object or an object whose existence is not visible | 2 |
| `conflict, idempotency_conflict` | Stale generation/life or key reused with changed content | 2 |
| `version_mismatch` | Use a compatible immutable client/service release; no DB fallback | 2 |
| `prerequisite_missing, unsupported, unavailable, not_implemented` | Do not launch; repair the named prerequisite or finish its owning lane | 69 |
| `integrity` | Preserve state/evidence and stop dependent work | 3 |
| `budget_exhausted, unscored` | Actual budget/policy result; never a manufactured low probability | 2 |
| `cursor_expired` | Reopen an authorized snapshot and resume from its cursor | 2 |
| `containment_unknown, deadline_exceeded` | No success/end/zero-survivor inference is permitted | 75 |
| `cancelled` | Operation cancelled; inspect its durable receipt before further work | 2 |

`retryable` permits retrying the **same request/key** after a transient outage,
not bypassing a refusal. Never reinterpret it as authority for a new launch.
An error reply that completes a reserved operation is final and has
`retryable=false`. A transient failure after reservation leaves it pending;
the same-key retry awaits that operation rather than completing a retryable
error receipt or executing the change again.

### Peer and human authentication

On Linux, authenticate SO_PEERCRED plus a lifetime-bound SO_PEERPIDFD, actual
host-side UID, process generation and containment membership. Match the
service-created `LaunchRecord`, not argv/environment/cwd/terminal ancestry.
Recheck before every operation and on delivery. Detached descendants retain the
lane UID/containment; identity drift never falls back to a parent. The client
checks mapped server credentials without requiring host /proc visibility.

On Darwin, require a live LOCAL_PEERTOKEN/audit-token generation proof tied to
the UID lease and launch record. A PID snapshot or UID alone is insufficient.
`PeerVerifier.Verify` returns a lifetime handle with `Facts/Alive/Close`;
unavailable native support leaves mutations and native launch unavailable.

Human authentication uses an administrator-enrolled WebAuthn public key with
user verification/presence, pinned origin and RP ID. A human socket, login UID,
terminal, session label or bearer file does not authorize an operation.
`human.challenge` stages a challenge; `human.confirm` verifies the actual
assertion and returns an opaque proof reference. The challenge binds config,
method, target, **intent digest**, base generation, expiry and one-use nonce.
Both `HumanChallengeRequest.request_sha256` and `ProofRef.request_sha256`
are the normal request digest above. The optional envelope `proof` is deliberately
outside that digest, avoiding a self-referential signature. A new proof for an
already completed identical idempotency key cannot perform the mutation again.

Challenge lifetime is at most 120 seconds. Consume the proof under the mutation
commit lock with the same principal, target, diff and generation. Read sessions
expire after five idle minutes, with a 30-minute absolute maximum, and are
revocable/configuration-scoped. Mutations need a fresh operation proof. Human
session IDs in events are record references, not cookies. An unconfined
compromised human desktop remains outside the OS threat model; no claim is made
that a hardware touch proves the browser display was honest.

### Authorization classes in the RPC catalog

Every class includes same-configuration, current binding, nonrevoked identity
and object-level visibility checks. The service derives actor/source; neither
is accepted in mutation bodies. `Scope.Request` is internal-only metadata
filled by the dispatcher and excluded from JSON. Scope.Source is also
server-derived (cli, dashboard, scheduler, watchdog or worker), never a client
source label. Modules use request metadata for durable
transaction/idempotency correlation.

| Class | Required authority |
| --- | --- |
| public | Non-sensitive version/readiness only; no paths, profiles or private checks |
| self | Authenticated lane's projection, or verified human; no role supplied by client can widen it |
| owner | Object/upload/operation belongs to the authenticated principal, or authorized human |
| tree | Own life and authentic starter descendants for lifecycle summaries; never level-wide |
| content | Per-object ACL plus life/tree class; sibling private mail, login/history and secrets excluded |
| human-endpoint | Administration endpoint only; bounded challenge/encrypted staging. No mutation authority before proof |
| human-proof | Independent verified operation-bound proof, current session/endpoint and atomic nonce consumption |
| human-read | Verified unexpired human browsing session; mutation proofs do not confer ambient future powers |
| parent | Actual recorded starter/ancestor with current delegation/control rights; human proof for mutations |
| spawn | Agent: 3 ≤ child level < caller level ≤ 6 and subset grants. Human root: valid single-use ticket redeemed by its issuing principal in the same configuration and human endpoint generation |
| control | Self stop/check/authorized own continuation, recorded ancestor control, or fresh human proof; never sibling control |
| reviewer | Authorized distinct supervisor/reviewer (or human proof), required diff/check/coverage receipts; no self-acceptance |
| relation | D7 direct parent upward, same-level/direct-parent siblings, ancestor downward; human proof may target any level |
| report-line | Direct starter upward; L5/L6 may use an exact granted human channel. L3/L4 have no human fallback |
| l6 | Authenticated current L6 life; D6 apply additionally requires the matching human approval |
| change-owner | Proposing L6 or verified human can inspect the staged change |
| judge-preview | Scoped preview using service-resolved policy/provider; cannot select a new secret/provider or enforce a preview verdict |
| resource | Named delegated cloud/resource capability and budget, with actual role blacklist policy; no raw credentials returned |

`grants.validate.parent_life_id` must equal the caller's authentic life.
All human authority-bearing mutations carry the operation-bound envelope proof,
including CLI control, records, root grants, tickets, secret changes and D6.
Challenge/confirmation/session setup and bounded blob/encrypted-secret staging
have their own authenticated staging flow; staging cannot launch or apply anything.
Human blob staging uses the current verified connection read session; it does
not consume an operation proof per begin/chunk/commit. The final committed
reference is then covered by the separate records.append/decisions.mutate proof.
Human dashboard controls are stop/resume/mark/mail through those same operations.
Do not infer a UID-based human exception.

## 3. Complete RPC catalog

There is no generic “execute command”, “open host path”, “append authoritative
event”, “force profile swap” or “call arbitrary legacy handler” method.
The table is exhaustive for schema 2. `params` and `result` are exactly the
named JSON objects in the schema appendix. M means a durable mutation (including
cost-incurring judge requests and upload leases); R means a read. Both can fail
with the error envelope above. Stub implementations return not_implemented.

| RPC | Request → response JSON object | Mode | Authorization | Implementation lane |
| --- | --- | --- | --- | --- |
| `health` | `HealthRequest` → `Health` | R | public | lb-v2-service |
| `identity.self` | `Empty` → `Scope` | R | self | lb-v2-identity |
| `operation.get` | `OperationGetRequest` → `Operation` | R | owner | lb-v2-service |
| `blob.begin` | `BlobBeginRequest` → `BlobUpload` | M | self | lb-v2-service |
| `blob.chunk` | `BlobChunk` → `BlobUpload` | M | owner | lb-v2-service |
| `blob.commit` | `BlobCommitRequest` → `BlobRef` | M | owner | lb-v2-service |
| `blob.read` | `BlobReadRequest` → `BlobChunk` | R | content | lb-v2-service |
| `human.challenge` | `HumanChallengeRequest` → `HumanChallenge` | M | human-endpoint | lb-v2-identity |
| `human.confirm` | `HumanConfirmRequest` → `ProofRef` | M | human-endpoint | lb-v2-identity |
| `human.session` | `HumanSessionRequest` → `HumanSession` | M | human-proof | lb-v2-identity |
| `ticket.issue` | `TicketIssueRequest` → `Ticket` | M | human-proof | lb-v2-identity |
| `grants.root` | `RootGrantRequest` → `GrantSet` | M | human-proof | lb-v2-grants |
| `grants.validate` | `GrantValidateRequest` → `GrantValidation` | R | parent | lb-v2-grants |
| `grants.get` | `GrantGetRequest` → `GrantSet` | R | content | lb-v2-grants |
| `grants.revoke` | `GrantRevokeRequest` → `Operation` | M | parent | lb-v2-grants |
| `grants.test-child` | `TestChildRequest` → `Operation` | M | parent | lb-v2-grants |
| `lane.start` | `StartRequest` → `Operation` | M | spawn | lb-v2-lifecycle |
| `lane.adopt` | `AdoptRequest` → `Operation` | M | spawn | lb-v2-lifecycle |
| `lane.resume` | `ResumeRequest` → `Operation` | M | control | lb-v2-lifecycle |
| `lane.turn` | `TurnRequest` → `Operation` | M | control | lb-v2-lifecycle |
| `lane.stop` | `StopRequest` → `Operation` | M | control | lb-v2-lifecycle |
| `lane.mark` | `MarkRequest` → `Operation` | M | reviewer | lb-v2-lifecycle |
| `lane.review` | `ReviewRequest` → `ReviewReceipt` | M | reviewer | lb-v2-lifecycle |
| `lane.clean` | `CleanRequest` → `Operation` | M | parent | lb-v2-lifecycle |
| `lane.archive` | `ArchiveRequest` → `ArchiveReceipt` | M | parent | lb-v2-lifecycle |
| `lane.status` | `LifeRef` → `Lane` | R | tree | lb-v2-lifecycle |
| `lane.list` | `ListRequest` → `LanePage` | R | tree | lb-v2-lifecycle |
| `lane.check` | `LifeRef` → `ProcessObservation` | M | control | lb-v2-lifecycle |
| `lane.loop` | `LoopRequest` → `Operation` | M | control | lb-v2-lifecycle |
| `lane.attach` | `AttachRequest` → `StreamFrame` | R | content | lb-v2-lifecycle |
| `lane.input` | `AttachInputRequest` → `Operation` | M | control | lb-v2-lifecycle |
| `event.tail` | `EventTailRequest` → `EventPage` | R | tree | lb-v2-lifecycle |
| `mail.send` | `MailSendRequest` → `Mail` | M | relation | lb-v2-messaging |
| `mail.list` | `ListRequest` → `MailPage` | R | content | lb-v2-messaging |
| `report.submit` | `ReportRequest` → `Mail` | M | report-line | lb-v2-messaging |
| `policy.get` | `PolicyGetRequest` → `EffectivePolicy` | R | self | lb-v2-policy |
| `policy.evaluate` | `PolicyEvaluateRequest` → `PolicyDecision` | M | self | lb-v2-policy |
| `guidance.select` | `GuidanceRequest` → `Guidance` | M | self | lb-v2-guidance |
| `judge.ask` | `JudgeRequest` → `JudgeReply` | M | judge-preview | lb-v2-judge |
| `judge.list` | `Empty` → `ConfigView` | R | self | lb-v2-judge |
| `brief.render` | `TemplateRequest` → `Briefing` | R | self | lb-v2-templates |
| `brief.start` | `BriefingRequest` → `Briefing` | R | self | lb-v2-templates |
| `config.read` | `ConfigReadRequest` → `ConfigView` | R | self | lb-v2-policy |
| `config.validate` | `Empty` → `OrgValidation` | R | self | lb-v2-policy |
| `org.validate` | `OrgValidateRequest` → `OrgValidation` | R | self | lb-v2-templates |
| `org.bootstrap` | `BootstrapRequest` → `Operation` | M | human-proof | lb-v2-templates |
| `org.change.propose` | `ChangeProposeRequest` → `ChangeRequest` | M | l6 | lb-v2-approval |
| `org.change.get` | `ChangeGetRequest` → `ChangeRequest` | R | change-owner | lb-v2-approval |
| `org.change.approve` | `ChangeApproveRequest` → `ChangeApproval` | M | human-proof | lb-v2-approval |
| `org.change.apply` | `ChangeApplyRequest` → `ChangeReceipt` | M | l6 | lb-v2-approval |
| `secret.key` | `Empty` → `SecretKey` | R | human-read | lb-v2-secrets |
| `secret.stage` | `SecretStageRequest` → `SecretStage` | M | human-read | lb-v2-secrets |
| `secret.import` | `SecretImportRequest` → `SecretInfo` | M | human-proof | lb-v2-secrets |
| `secret.rotate` | `SecretRotateRequest` → `SecretInfo` | M | human-proof | lb-v2-secrets |
| `secret.revoke` | `SecretRevokeRequest` → `Operation` | M | human-proof | lb-v2-secrets |
| `secret.list` | `Empty` → `SecretList` | R | self | lb-v2-secrets |
| `dashboard.tree` | `DashboardQuery` → `TreeView` | R | human-read | lb-v2-dashboard |
| `dashboard.raw` | `DashboardQuery` → `RawView` | R | human-read | lb-v2-dashboard |
| `dashboard.decisions` | `DashboardQuery` → `DecisionView` | R | human-read | lb-v2-dashboard |
| `dashboard.refusals` | `DashboardQuery` → `RefusalView` | R | human-read | lb-v2-dashboard |
| `dashboard.plugins` | `DashboardQuery` → `ResourceView` | R | human-read | lb-v2-dashboard |
| `dashboard.resources` | `DashboardQuery` → `ResourceView` | R | human-read | lb-v2-dashboard |
| `dashboard.lifecycle` | `DashboardQuery` → `LanePage` | R | human-read | lb-v2-dashboard |
| `dashboard.approvals` | `DashboardQuery` → `ApprovalView` | R | human-read | lb-v2-dashboard |
| `records.query` | `RecordQuery` → `RecordPage` | R | content | lb-v2-integrate |
| `records.get` | `RecordGetRequest` → `Record` | R | content | lb-v2-integrate |
| `records.append` | `RecordAppendRequest` → `Record` | M | self | lb-v2-integrate |
| `decisions.mutate` | `DecisionMutateRequest` → `Record` | M | human-proof | lb-v2-integrate |
| `records.import` | `TransferRequest` → `Operation` | M | content | lb-v2-integrate |
| `records.export` | `RecordQuery` → `BlobRef` | R | content | lb-v2-integrate |
| `store.verify` | `VerifyRequest` → `Verification` | R | human-read | lb-v2-service |
| `store.rebuild` | `RebuildRequest` → `Operation` | M | human-proof | lb-v2-service |
| `box.launch` | `BoxLaunchRequest` → `Box` | M | resource | lb-v2-integrate |
| `box.run` | `BoxRunRequest` → `Operation` | M | resource | lb-v2-integrate |
| `box.harvest` | `BoxControlRequest` → `BlobRef` | M | resource | lb-v2-integrate |
| `box.end` | `BoxControlRequest` → `Operation` | M | resource | lb-v2-integrate |
| `box.list` | `ListRequest` → `BoxPage` | R | resource | lb-v2-integrate |
| `migration.plan` | `MigrationPlanRequest` → `MigrationPlan` | R | human-read | lb-v2-migration |
| `migration.apply` | `MigrationApplyRequest` → `Operation` | M | human-proof | lb-v2-migration |
| `upgrade.plan` | `UpgradePlanRequest` → `UpgradePlan` | R | human-read | lb-v2-packaging |
| `upgrade.apply` | `UpgradeApplyRequest` → `Operation` | M | human-proof | lb-v2-packaging |
| `doctor` | `Empty` → `Health` | R | self | lb-v2-admin |

### File transfer, reads and streams

CLI inputs are files in the client's own boundary. The client sends bounded
bytes; the service never opens an arbitrary client path. Blob classes are
`task,prompt,report,artifact,capture,transcript,policy,manifest,judge_request,
judge_raw,archive,record`. The service assigns class-specific provenance and
ACLs. A caller cannot label a mutable upload as primary capture, policy, archive
verification or approval evidence. Such classes require the matching trusted
worker. Task secrets/login material never use generic blobs.

`blob.begin` reserves the declared size and SHA-256; `blob.chunk` accepts
contiguous offsets, a chunk hash and at most 262,144 **decoded** bytes.
Same-offset identical replay is idempotent; conflicting bytes, holes and overflow
refuse. `blob.commit` verifies total length/hash before any event can reference
the object. Object limit is 64 MiB; larger archives use a manifest of bounded
objects, not a silent oversized exception. Uploads expire after 15 minutes.
`blob.read` returns at most one chunk; no server path, symlink or auth slot is
a read target. Screening and ACL denial must not pretend empty successful data.

The approved capture reader rule (H1) is:

> The human who redeemed the tree's root ticket reads any lane in their own
> tree. “Next layer only” binds supervisors, not that human. The reader set of
> a lane's capture blobs is exactly that human owner plus the lane's DIRECT
> parent. Refuse the grandparent, a sibling, another human, a peer L5, and any
> other scope.

Both `blob.read` and `lane.attach` in read mode enforce this rule for captured
stdout and stderr. The human uses the existing verified human-read session;
ownership comes from the root launch's consumed ticket and retained operation.
The direct parent is the protected `ParentLifeID`, not any member of the starter
chain or another lane at the same level. Authentication, current scope, immutable
object ACLs, capture provenance and byte/hash checks remain required. A blob ID
or a reference in mail confers no read authority. Internal capture retention and
teardown keep their existing narrowly authenticated worker/service authority.

For `event.tail` with `follow=false`, return `EventPage`.
With follow=true return its snapshot in the ordinary response, then framed
`StreamFrame` records on that connection. `lane.attach` returns an initial
StreamFrame followed by the same frame protocol. Exactly one event/chunk is
present on data frames, neither on end/error frames. `index` increases from 1;
`cursor` is opaque, authenticated, configuration / principal / filter / generation
bound and exclusive. `since` excludes that sequence. A cursor plus incompatible
filters/since refuses. Limits are 1–200 per page, 256 queued stream frames and
4 MiB queued bytes; overflow closes with an explicit resumable cursor/error.
Cancellation closes only the watcher, not the lane.

Select and authorize the life **and run before** subscription, then filter
before `until`. Only the selected run's service-origin event of that kind
ends follow; an older end, appended observation or hidden sibling end cannot.
The parent must receive a committed authentic child end within two seconds
under the healthy two-ladder/20-agent load. Capture commit/receive monotonic
times separately from earlier process cleanup. Disconnect/timeouts are errors,
never successful end evidence. Attach input/resize is a separate `lane.input`
mutation with fresh authority; the stream itself cannot stop or impersonate a
runner and never exposes its PTY/tmux socket.

### State and lifecycle ordering

`Store.Transact` atomically validates authenticated request metadata, CAS
comparisons, the closed event schema and idempotency, then appends events,
updates projections and records the outbox. The SQLite writer is service-only;
a single transaction must not wait for a judge, model, file upload or process.
Use per-life serialization for launch/stop/turn/watchdog and short DB transactions.
An outbox effect has exactly one of launch/stop/deliver/clean/swap/worker/
apply-change/migration/upgrade/rebuild populated and
an immutable effect ID. Worker completion reconciles that ID; crash recovery
never reexecutes a possibly running process without observing its containment.

State values are `preparing,running,stopping,verifying,idle,profile_wait,lost,
accepted,merged,abandoned`; `cleaned` is a retained-record flag.
Operation status is `pending,running,succeeded,failed,cancelled`.
No pending receipt is completion. Creation reserves a new life and run 1.
A successful prepare/bind/release reaches running. A truthful terminal
observation with zero survivors reaches verifying (or idle for a completed
scheduled turn); unknown containment reaches lost/stopping. Explicit reviewed
mark permits verifying → accepted → merged; abandonment preserves work.
Resume/turn requires an ended, uncleaned, non-merged/non-abandoned life with a
known session and zero survivors. Starting after clean always creates a new
life, even if the display name is reused.

Start/adopt validates strict-lower level, current policy, grants, budget,
driver/credential availability and exact task/template inputs before preparing
the sandbox. Adoption imports only a quiescent legacy session; no running host
process is blessed. Start by a human consumes a ticket bound to root grants,
level and role. Human adoption also consumes such a ticket (see AdoptRequest).
`start`/briefing alone launches nothing and registers no ambient shell.

The release sequence is:

1. Commit operation/lane/grant intent and immutable source objects.
2. Materialize through the confined data worker; prepare a nonexecuting launch
   gate with separate UID, namespace/profile, network, cgroup and closed FDs.
3. Persist `identity.bound` and verify the matching launch, life, grant hash,
   endpoint/process generation and gate. Obtain a `LaunchPermit`.
4. Release that exact gate once, capture vendor bytes externally, record actual
   start, and obtain the vendor session mapping before any resume is eligible.
   If the service crashes between release and recording, reconcile by launch
   ID/containment; never release another process on an uncertain retry.
5. On exit/stop, revoke run endpoints, observe containment, record the real exit,
   prompt state and survivor count, then release transient slots. Do not recycle
   UID/workspace leases or claim an end while observation is unknown.

`ProcessObservation.state` is `prepared,running,exited,unknown`.
`survivors` is optional only when unknown; omission is not zero. Exit code is
present only for a known exit; signal is present only for a signal termination.
Prompt status is `not_written,written,cut,unknown,completed`; written never
means read. End reason is `exit,stop,timeout,limit,dropped,revoked,service_lost,
capture_full,launch_failed`. Preserve real vendor exit codes.

Review requires an authorized actor other than the task executor, exact diff,
required check receipts, record inventory, and explicit refusal/suspicion
resolutions. Receipt IDs are service-created; clients cannot manufacture a
passing ReviewReceipt or an archive verification. Marking merged records a
decision and performs no Git merge/deployment. Clean requires quiescence,
merged/abandoned lifecycle state, immutable archive manifest, hash/read-back receipt,
and an unforced owned-object removal. It retains events, inputs, capture,
reports and archive references. Dirty or unowned work is preserved.

## 4. Event schema v2

Every event has the common `Event` envelope in the appendix. `seq` is a
strictly increasing configuration-wide commit order. Event ID deduplication
compares bytes/digest, never just the ID. `actor` is the authenticated requester
or actual service/scheduler/watchdog/worker principal; `requested_by` preserves
the original causal requester. Actor kinds are `lane,human,service,scheduler,
watchdog,worker`. Lane actors carry life/level/role; service principals do not
borrow the first carried mail sender. Mail retains its own sender independently.

The starter chain is ordered root → … → direct parent and **excludes self**;
root has an empty chain, root_life_id=self, no parent and starter_event_seq=0.
For a child, starter_event_seq identifies its direct parent's authentic
created/adopted event, which precedes the child. Parent/root/chain are immutable
per life, constructed from service records, never imported client claims.
For no-life administrative events these fields use empty/zero values as
documented in the appendix. Requested/observed times are service observations;
recorded_at is commit time. Request ID, operation ID and logical turn correlate
related events without conferring authority.

Origins are `service,observation,legacy_import`. Only trusted service emission
may produce authoritative lifecycle/identity/grant/approval kinds. Public
`event append` maps to `records.append` with observation origin, and its
resulting event is only `record.appended`. Imported old envelopes remain exact
bytes in a migration object; they never synthesize an active starter graph.

All event kinds, payload shapes and emitters are enumerated below. Payload
fields are the appendix's complete named object, with no additional fields.
“Emitter” is trusted service code, not an RPC that lets a lane append that kind.

| Kind | Payload | Emitter |
| --- | --- | --- |
| `service.started` | `ServiceEvent` | lb-v2-service |
| `service.recovered` | `ServiceEvent` | lb-v2-service |
| `operation.accepted` | `OperationEvent` | lb-v2-service |
| `operation.completed` | `OperationEvent` | lb-v2-service |
| `operation.failed` | `OperationEvent` | lb-v2-service |
| `human.challenge` | `HumanChallenge` | lb-v2-identity |
| `human.confirmed` | `ProofRef` | lb-v2-identity |
| `human.proof.used` | `ProofUseReceipt` | identity/store atomic guard commit |
| `human.session` | `HumanSession` | lb-v2-identity |
| `ticket.issued` | `Ticket` | lb-v2-identity |
| `ticket.redeemed` | `Ticket` | lb-v2-identity |
| `lane.created` | `LaunchEvent` | lb-v2-lifecycle |
| `lane.adopted` | `LaunchEvent` | lb-v2-lifecycle |
| `launch.prepared` | `LaunchEvent` | lb-v2-lifecycle |
| `launch.planned` | `LaunchPlanRecord` | lifecycle planner / service store |
| `loop.reserved` | `LoopTurnCause` | service store ReserveLaunch loop writer |
| `launch.failed` | `LaunchFailedEvent` | lb-v2-lifecycle |
| `lane.started` | `LaunchEvent` | lb-v2-lifecycle |
| `lane.resumed` | `LaunchEvent` | lb-v2-lifecycle |
| `lane.turn` | `TurnEvent` | lb-v2-lifecycle |
| `prompt.observed` | `TurnEvent` | lb-v2-lifecycle |
| `lane.stopping` | `StateEvent` | lb-v2-lifecycle |
| `lane.ended` | `RunEndEvent` | lb-v2-lifecycle |
| `lane.lost` | `RunEndEvent` | lb-v2-lifecycle |
| `lane.state` | `StateEvent` | lb-v2-lifecycle |
| `lane.policy` | `PolicyAdvanceEvent` | service/store policy refresh coordinator |
| `lane.cleaned` | `CleanEvent` | lb-v2-lifecycle |
| `lane.reviewed` | `ReviewReceipt` | lb-v2-lifecycle |
| `lane.loop` | `LoopRequest` | lb-v2-lifecycle |
| `run.observed` | `ProcessObservation` | lb-v2-lifecycle |
| `capture.appended` | `CaptureRecord` | lb-v2-lifecycle |
| `capture.gap` | `CaptureGap` | lb-v2-lifecycle |
| `capture.bound` | `CaptureBinding` | installed helper attestation / lifecycle planner |
| `capture.refused` | `CaptureBinding` | lifecycle planner / service store |
| `capture.closed` | `CaptureAppendReceipt` | outside capture supervisor / service store |
| `grants.issued` | `GrantEvent` | lb-v2-grants |
| `grants.revoked` | `GrantEvent` | lb-v2-grants |
| `data.materialized` | `Materialization` | lb-v2-grants |
| `secret.imported` | `SecretEvent` | lb-v2-secrets |
| `secret.rotated` | `SecretEvent` | lb-v2-secrets |
| `secret.revoked` | `SecretEvent` | lb-v2-secrets |
| `secret.injected` | `Injection` | lb-v2-secrets |
| `credential.leased` | `CredentialEvent` | lb-v2-secrets |
| `credential.released` | `CredentialEvent` | lb-v2-secrets |
| `watchdog.limit` | `WatchdogEvent` | lb-v2-watchdog |
| `watchdog.waiting` | `WatchdogEvent` | lb-v2-watchdog |
| `watchdog.swapped` | `WatchdogEvent` | lb-v2-watchdog |
| `watchdog.cancelled` | `WatchdogEvent` | lb-v2-watchdog |
| `mail.queued` | `Mail` | lb-v2-messaging |
| `mail.delivered` | `MailReceipt` | lb-v2-messaging |
| `mail.returned` | `MailReceipt` | lb-v2-messaging |
| `report.submitted` | `Mail` | lb-v2-messaging |
| `channel.delivered` | `Delivery` | lb-v2-messaging |
| `channel.failed` | `Delivery` | lb-v2-messaging |
| `policy.evaluated` | `PolicyDecision` | lb-v2-policy |
| `judge.completed` | `JudgeReply` | lb-v2-judge |
| `guidance.selected` | `Guidance` | lb-v2-guidance |
| `org.change.proposed` | `ChangeEvent` | lb-v2-approval |
| `org.change.approved` | `ChangeEvent` | lb-v2-approval |
| `org.change.applied` | `ChangeEvent` | lb-v2-approval |
| `org.change.rejected` | `ChangeEvent` | lb-v2-approval |
| `archive.verified` | `ArchiveReceipt` | lb-v2-lifecycle |
| `blob.committed` | `BlobRef` | lb-v2-service |
| `record.appended` | `Record` | lb-v2-integrate |
| `decision.changed` | `Record` | lb-v2-integrate |
| `migration.completed` | `MigrationEvent` | lb-v2-migration |
| `upgrade.applied` | `UpgradePlan` | lb-v2-packaging |
| `worker.completed` | `WorkerEvent` | lb-v2-integrate |
| `worker.failed` | `WorkerEvent` | lb-v2-integrate |
| `box.changed` | `Box` | lb-v2-integrate |
| `identity.bound` | `LaunchRecord` | lb-v2-identity |
| `identity.revoked` | `LaunchRecord` | lb-v2-identity |
| `runner.session` | `Session` | lb-v2-lifecycle |
| `helper.allocated` | `HelperLease` | lb-v2-admin |
| `helper.released` | `ReleaseReceipt` | lb-v2-admin |
| `org.bootstrapped` | `ConfigView` | lb-v2-templates |

LaunchEvent retains grants_sha256/grant_set_id, policy generation, template
source/generation/rendered hash, task hash, backend, endpoint generation,
names-only secret injection and its exact grant/source-version correlation.
The secret arrays are parallel and in request order; the two name arrays split
environment/file delivery. Never record values or an environment snapshot.
`runner.session` binds the vendor-issued conversation to the existing life.
CaptureRecord offsets/hash refer to exact outside-captured bytes; transcript
replacement and gaps remain explicit. A lane-authored file cannot overwrite
primary capture.

Lifecycle/control/status events are visible to the life and authentic
ancestors. Raw content additionally checks the object ACL; unrelated and sibling
subtrees do not gain raw logs/mail merely from level or common root. Human
administrative/secret/key/ticket events are restricted to the human/service.
Parent secret views contain only the child's delegated names/handles; store
metadata is not a secret-value API. The same visibility function is used by
tail, status, state, search, briefing, artifacts and dashboard routing.

## 5. Grants, data materialization and secrets

Grant requests come from a retained file. Data fields are parent grant ID,
beneath-root relative path (`.` allowed), access `ro|rw`, delivery
`copy|mount`, destination, delegation, expiry and optional publication ID.
Destinations are collision-free logical `/work/<id>` or `/data/<id>`, not
home/temp/runtime/policy/socket parents. The main workspace is `/work/main`.
Reject traversal, ambiguous aliases, overlapping rights, nested writable
exceptions, escaping symlinks/hardlinks, special files and injected Git
administration. Resolve through opened identities, never string prefixes.

Child rights, expiry, publication, network/channel/profile/secret selection
and redelegation are subsets of the actual starter's recorded grants. Level
does not widen a grant. Copy is independent and default; a read-only source can
be read into private scratch but cannot become a writable live source.
Materialization records actual source/destination identities, object/snapshot
hash and workspace ID. Revalidate before every release/resume/turn, including
revoked ancestors and policy generations. A parent's sealed post-exit lease
may preserve previously delegated scope; missing/revoked authority cannot.

RootGrantRequest.manifest references RootGrantManifest
(`schema:"laneboss.root-grants.v2"`). Its root entries use the effective grant
shapes with empty `id,parent_grant_id`; the service issues IDs. A current human
read session may stage class `manifest` through blob begin/chunk/commit. It
retains the human owner, owner-only audience and observation provenance; the
class label grants no enrollment, policy or service-receipt authority. The
separate grants.root confirmation still covers the exact manifest and budget.
Lane and worker uploads cannot select this human proposal class. Data source
objects are committed uploaded ObjectManifests or explicitly administrator-
enrolled broker volume IDs, never host paths. Profile/secret/channel/endpoint
handles must already exist in protected enrollment. Root approval covers their
complete selection and budget. Each data ObjectManifest has
`schema:"laneboss.objects.v2"`, relative entries of kind `file|directory|symlink`,
ordinary modes without setuid/capabilities, content hashes and checked internal
relative link targets. No devices, sockets, FIFO, external links or preserved
unknown ACLs. Hash the complete manifest and bytes before activation.

Independent repositories have private object DBs and requested reachable
history only: no shared clones, host alternates/common .git, credential remotes,
hooks/filters or implicit submodules/LFS grants. A subtree/file grant is a tree
snapshot, not a whole Git history. Publication is separate reviewed diff/bundle
import in a confined worker; it cannot execute child code with parent rights.
DataWorker.TestChild uses the child's effective grants intersected with current
parent/owner authority. Additional test inputs need a new explicit grant
decision; do not silently union siblings' private inputs.

Linux mount delivery requires a registered export with pinned object identity,
recursive read-only handling or an exclusive live writer lease. Native Darwin
supports independent copies/APFS clones only and returns unsupported for mount,
with a copy/Linux route. Revocation blocks new operations, stops affected
descendants, verifies quiescence and removes leases/endpoints before narrower
restart. It cannot make a lane forget already-read copies.

Task secrets use SecretDelegation, separate from ProfileDelegation. A name
selects one granted source/version; no wildcard/backend credential, host-shell
enumeration or inference from existing env names is allowed. Delivery is
`env|file`; env target is a nonreserved variable name, file target is a
relative name under a read-only private runtime secret directory. HOME, PATH,
TMPDIR, vendor-home, loader, launcher/binding and control variables cannot be
overridden. Inject only selected names immediately before release, outside
worktrees. Record Injection names/grant IDs/version/outcome; values remain in
protected memory/runtime slots and are excluded from events, argv, prompts,
source archives and fixture homes.

The default native backend uses AES-256-GCM with a new random 96-bit nonce per
record/version and associated data binding config, name, version and key ID.
It keeps key material separate from encrypted records, crash-safe atomic
updates, exclusive refresh/rotation ownership, protected unlock at restart and
separate recovery-key backup. No plaintext-key fallback is allowed.
SecretMaterial has `json:"-"`; only the credential worker consumes it.
An optional Infisical backend must implement SecretBackend without changing
delegation; its deployment is not required or provisioned by this build.

Secret import uses the human endpoint: secret.key advertises an ephemeral
X25519 public key; secret.stage accepts X25519 + HKDF-SHA256 + AES-256-GCM
ciphertext (maximum 64 KiB decoded), not a plaintext generic blob.
HKDF info is `laneboss.secret-stage.v2`; associated data is JCS of
`{config,key_id,name,version}`; salt is the 32-byte SHA-256 of that associated
data. The nonce is 12 random bytes; ciphertext includes the GCM tag. Stage IDs
expire after 120 seconds and bind the submitting verified human session.
Import/rotate proof binds the stage ID/name/version; the worker decrypts only
there and rejects wrong associated data. Stage ciphertext is short-lived
protected storage, not a public log/blob. Encrypted-at-rest format and staging
format are distinct. A lane may read a secret deliberately supplied to it;
this does not promise hiding its own key from its tools.

## 6. Isolation launcher, helper and runners

The frozen `api.Launcher` interface is Prepare(spec) → PreparedLaunch,
Launch(prepared, permit) → ProcessHandle, plus Probe/Observe/Stop/Abort/Collect.
Every method takes context and returns an error. LaunchSpec is generated only
by the service from current grants, materialization, injection, budget, runtime
manifest and immutable IDs. Kind is agent or worker; exactly one of RunnerPlan
or WorkerPlan is present. Agent launch accepts only the two frozen drivers.
Worker launch executes a fixed leased service job under its narrowly bounded
worker UID/grants, with no agent identity or broader state authority. Git/test/
render workers therefore share OS enforcement without becoming a third agent
driver. LaunchSpec is not a client RPC.
Prepare must execute no agent code. Launch requires a committed matching
LaunchPermit and opens the gate once. An arbitrary caller cannot submit argv
to a root helper: HelperLaunchRequest carries only an authenticated prepared
spec ID/digest and lease, and the helper runs fixed installed bootstrap code,
drops UID/capabilities, then invokes the pinned unprivileged launcher.
The root helper, bootstrap, bwrap, sandbox-exec and outer launcher run with a
fixed minimal environment containing no granted task-environment values. Apply
granted values only as the envp of the final unprivileged vendor execve, after
the UID and capability drop and after bwrap/Landlock or sandbox-exec isolation
setup has completed. Holding a private descriptor or buffer in the helper is
not permission to export its value into any earlier process environment.

Linux baseline is capability-proved Linux 6.6/ABI 3, bwrap ≥0.8, userns, cgroup v2,
separate service/lane UIDs and controlled network/PID/IPC/mount namespaces.
The production implementation ports the measured `spikes/linux-iso` source on
`lb-spike-linux-iso`, especially `b38c634`; the spike's Ubuntu 24.04.5,
bwrap 0.9.0, ABI 8 results are prior feasibility evidence, not this product's
acceptance or proof of ABI 3. Probe actual behavior and fail before release
when any required primitive is missing.

One administrator setup installs accounts/leases, immutable helper/systemd
units, cgroup/network plumbing and, on restriction-on Ubuntu, a bwrap-only
AppArmor userns profile. Keep the host restriction enabled; no broad setuid
bwrap or host-wide switch. An unprofiled namespace control must remain denied.
The namespace hides host state/home/sibling data; Landlock further restricts
read/execute and writes (including REFER/TRUNCATE). Apply no_new_privs,
capability dropping, reviewed escape-syscall denies and close inherited FDs/cwd.
Ordinary new binaries, builds, Git, network clients, own loopback, temp/cache,
detachment and own-process signaling remain usable. ABI 3 network/IPC safety
comes from namespaces/UID/packet controls, not unavailable later Landlock rules.

Darwin uses a dedicated UID per life, LaunchDaemon/helper, deny-default
sandbox-exec, independent copies, protected policies and native peer lifetime
verification. No Keychain/Apple Events/accessibility/launchd escape grant.
Per-UID packet policy plus actual recipient/listener leases must block host,
sibling and metadata endpoints, including IPv6/public-host addresses; unsupported
local-port behavior routes to Linux/VM. Failure leaves native isolation
unavailable. A Darwin compile is not native acceptance.

Run containment is cgroup/PID namespace on Linux and proved UID/kernel
supervision on Darwin, not a sampled ancestry list. Stops cancel watchdog
intent, drain captures, revoke endpoints and verify actual zero survivors.
Unknown process observation retains leases. All levels meet the same OS
boundary with hooks absent/allowing and vendor inner sandbox disabled.
The primary service never executes repository scripts or Git.

The only Driver values are `claudock-cli` and `codex`.
Runner.Start/Resume/Turn return a RunnerPlan; the adapter does not launch outside
the isolation gate. Start/resume/turn carry the same life, private Home.ID,
history ID, logical cwd and session mapping. Plan argv contains no secrets.
Private vendor home/cache/history is separate from a run-scoped CredentialSlot.
The service pins actual executable/version/hash and restricts generated policy
overlays; basename/PATH alone is insufficient. Ordinary tools remain unrestricted
except explicit blacklist policy and OS grants.

Claudock invokes the actual `claudock run <selected-profile> -- …` interface,
with only that profile's projected registry, explicit conversation/session and
headless-token/helper/file mode proved against the pinned vendor. Codex captures
its actual structured vendor conversation ID and resumes it explicitly; never
invent a start UUID flag or use shared `--last`. Subscription/OAuth and API
modes need separate evidence. A file-login refresh token has one lease owner;
another lane waits, never receives an unsynchronized refresh copy.
No paid fallback, third driver, host Keychain or shared ~/.claude/~/.codex mount.

SessionFromCapture and LimitFromCapture consume primary CaptureRecords from
the outside supervisor. A recognized structured provider limit and real
exit/room evidence can produce LimitSignal. Quoted model/tool “limit” text,
guard refusals, auth errors and edited lane transcripts cannot.
All output is byte-ranged/hashes with explicit cut/full/gap/coverage status.
A full capture spool is a recorded incomplete stop, never silently dropped bytes.

Watchdog.ObserveLimit serializes with manual control, quiesces the old run,
checks current delegated profile room/provider/model affinity and remaining
budget and calls the **internal** Continuation interface with its durable intent
and cancellation epoch. Lifecycle claims that intent and owns the single
replacement-slot acquisition/handoff; watchdog does not acquire a loose slot.
There is no lane-facing swap method. ProfileSwap plus the next LaunchEvent
records from/to, limit capture/hash, room evidence, cause, operation and prior
run. The logical turn/session/worktree/history stay fixed; only run and slot
change. This increments no task failure/retry counter and resets no budget.
Mail belongs to the logical turn and is acknowledged only on actual completed
delivery; uncertain prompts remain uncertain. No-room enters profile_wait with
bounded service backoff; stop/abandon/clean/revocation cancels future continuation.

## 7. Judgment, blacklist and per-turn guidance

`api.Judge` exposes Fit and Evaluate; both receive JudgeRequest and context.
Request purpose is `blacklist|guidance|preview`. Rule text, exact command
bytes/argv/tool/declared paths, task and decisions are **named data**, separated
from fixed trusted instructions and true/false membership criteria. Criteria
IDs are lookup/version keys, never the model's only instructions. The service
resolves JudgeContext from the live scope; a hook cannot submit a different
level, grant, policy generation or provider credential.

Provider identifiers are `typesafe` and `clef-sglang`. TypeSafe uses the
actual Jev state/instructions/criteria Noul probability contract. Clef uses the
self-hosted `/v1/systemone` route with pinned `Cloudflare/clef-flash` weights,
serving image, tokenizer and adapter hashes. R101 chooses self-hosted evaluation:
there is no hosted Cloudflare adapter, account/token prerequisite or automatic
hosted fallback. Actual endpoint/credential handles stay in protected config.
Under **R108**, an unspecified provider selects `clef-sglang` and the full model
name `Cloudflare/clef-flash`. An unavailable Clef deployment returns a typed
unavailable/unscored result under the existing outage rules; it never selects
TypeSafe automatically. Keep tokenizer-fit, complete-response, deadline and
threshold-calibration checks. The approximately 302-item Clef-only corpus
calibrates the deployed stack; it is not a provider-selection contest or a
shadow-promotion gate. Changing the selected provider remains a D6 resource.
The request's selected model is a full name; reported_model is retained but a
server echo does not prove deployed weights. Preserve raw provider bytes as
protected objects and normalized schema separately.

The complete serialized provider request is at most 262,144 bytes; at most 12
questions per batch. Fit proves the full formatted request with the pinned
tokenizer and actual configured context window before sending. Unknown fit,
overflow, missing / duplicate / nonfinite / out-of-range probabilities, partial or
truncated responses, withholding, timeout or exhausted cost cap are explicit
unavailable/unscored results. No truncation, probability zero substitution or
silent provider switch. Judgment probability is optional only for unscored;
valid scored values are finite in [0,1]. Complete answers correspond bijectively
to rule/decision IDs. Response status is `scored|partial|unavailable`;
per-question status is `scored|unscored`. Latency includes queue/transport/
validation; request bytes/tokens and actual cost are recorded, not inferred zero.

Effective deny rules are the union of org, own (level, role), and every higher
level's scoped roles. A missing role layer inherits the org baseline; no numerical
N+1 scalar inheritance is invented. Invalid policy fails configuration before
dispatch. Twelve Laneboss-first workflow entries are the only seeded pack;
no implicit command/tool permission list or broad network/secret ban.
Legacy patterns/argv_words are historical migration input; **active membership
is judged** under this build brief's D2 reading. There is no second deterministic
pattern refusal after a semantic allow. Only explicit refuse-band entries deny;
warn-band rules only warn. Unknown ordinary commands are not refused for absence
from a list.

Resolve threshold/criteria/calibration at each rule's defining scope so a child
cannot weaken inherited policy. Initial configurable recommendations are match
0.85, uncertainty [0.40,0.60], 30-second cache TTL, two-second total blacklist
deadline and five-second total guidance deadline (including queue/store wait).
A provider/stack-specific calibration receipt is required before live
enforcement; the numeric recommendations are not evidence of Clef accuracy.
All changes are D6 resources. Cache binds full raw digest, normalization, tool,
cwd, role/instance, grants/policy/rules, model/deployment/tokenizer, criteria,
threshold and declared context dependencies; hit records point to the original
receipt. Normalization never executes expansions or drops quoted arguments.

Uncertain probabilities remain visible; unresolved/partial judgments are
unscored. Only an explicitly org-marked **critical refuse-band** rule fails
closed on unscored judgment, and only within that rule's applicable role/scope.
Other entries allow with notice/audit; warn never blocks. Result aggregation is
refuse > warn > allow. An actual matching explicit refuse rule refuses with
its Instead route. A policy/audit outage never weakens OS/service authority.

Judge skipping is an allow-only optimization from D6-approved SkipEntry
sources bound to the exact effective rules/context. It may skip only when no
applicable deny/critical unresolved rule can be overridden. A miss invokes the
judge, never refuses. Rule/context updates invalidate skip/cache eligibility.
No program-name-based safe list or local agent-edited skip file is authority.

Every logical prompt-delivery turn (initial start, resume, mail/loop turn)
invokes guidance selection once, including a visible unavailable result.
Profile continuation retains the same logical turn and does not duplicate
mail/prompts or charge a second independent selection. Retrieve bounded
applicable DecisionCandidates; the judge scores relevance. At the service's
clock time, age=max(0, now-effective_at), weight=2^(-age/H), default H=14 days.
Rank nonbinding reminders by weight × relevance and offer at most five.
WeightedScore is sum(weight × relevance)/sum(weight); it is absent when
selection is unscored. An actually empty candidate set yields zero, and valid
scored zero probabilities remain zero; neither stands in for unavailable data. Current binding
decisions/approvals/blacklists are retained separately regardless of age and do
not consume the five reminder slots. There is no reminder cooldown.
Guidance is advisory and cannot grant authority or refuse by itself.

## 8. D6 exact-change approval

All canonical org assets, including scripts/tools/notes/plugins, templates,
configuration, blacklist/skip/threshold sources and channel grants, are owned by
the service. No lane, including L6, gets their writable paths.
Only an authenticated current **L6** can propose/apply an update. A lower level
may send an inert artifact up its report line.

ChangeProposeRequest carries org ID, base generation, reason object and all
ResourceDeltas. Actions are `add|replace|delete`; path is an org-relative source
path, mode is ordinary file mode, before_sha256 is required for replace/delete,
and after is present only for add/replace. The service resolves current source
ownership, confines the renderer, stages source plus **all derived effects**,
records the exact renderer artifact and returns a ChangeRequest with diff and
manifest hash. A client cannot hand-edit generated settings as a shortcut.

The manifest hash is SHA256(JCS of
`{org_id,base_generation,files,derived,renderer}`), with file and derived lists
sorted by normalized path and no duplicates. All referenced after bytes must
already be committed and hash-verified. This is what the human reviews.
The human approves `org.change.approve` with an envelope proof bound to the
change ID, manifest hash and base generation. ChangeApproval records the
approver key, L6 life, nonce, time and expiry. Approval lifetime is at most
ten minutes and cannot outlive the staged change (24-hour maximum).

Under the apply lock the service rechecks current L6 identity, org/base,
staged exact bytes/generated outputs, renderer pin, unconsumed approval,
nonce/expiry and unchanged manifest. It atomically installs the approved
generation and records approval/application/idempotency receipts. Rendering
after approval may only validate identical retained outputs; any new effect or
different byte requires a new staged diff and fresh approval. Missing proof,
L5/L4/L3 requester, wrong org/hash, rebase, replay or expiry changes nothing.
An old “yes”, active read session or approved previous script never covers a
future change. Approving changes to approval policy itself uses the current
policy. Initial administrator enrollment is the only baseline exception.

## 9. Dashboard data API and messaging

The service hosts a human-only HTTPS UI, outside lane-reachable network/IPC.
Use a fixed installed origin/RP; no permissive wildcard Origin, CORS or local
agent port. Browser authentication maps the verified human.session to a Secure,
HttpOnly, SameSite=Strict cookie; it is never returned by a lane data endpoint,
event or script-readable storage. Origin/CSRF and fresh operation-bound proof
apply to every mutation. On a Unix human connection, successful human.session
binds read authority to that connection and key; ID alone is not bearer
authority. Closing it drops that authority. HTTP cookies stay outside RPC JSON.

`POST /api/v2/rpc` carries the exact Request envelope and returns Response.
The HTTP wrapper exposes only the human-authorized subset of the RPC catalog;
it does not proxy helper/internal methods. Bind config to the installed
dashboard session and refuse envelope conflicts. HTTP statuses are 400 for
shape, 401/403 auth, 404 hidden/missing, 409 conflicts, 503 unavailable and 500
integrity; always include the typed error. Successful RPCs return 200 even when
the Operation remains pending. No human-facing route pretends pending is done.

For convenience the following **read-only** GET routes accept the documented
DashboardQuery fields as query parameters, with config bound to the session,
and return the corresponding result object (not arbitrary SQL or HTML):

| HTTP route | Socket method / response |
| --- | --- |
| `/api/v2/tree` | dashboard.tree / TreeView |
| `/api/v2/raw` | dashboard.raw / RawView |
| `/api/v2/decisions` | dashboard.decisions / DecisionView |
| `/api/v2/refusals` | dashboard.refusals / RefusalView |
| `/api/v2/plugins` | dashboard.plugins / ResourceView |
| `/api/v2/resources` | dashboard.resources / ResourceView |
| `/api/v2/lifecycle` | dashboard.lifecycle / LanePage |
| `/api/v2/approvals` | dashboard.approvals / ApprovalView |

`GET /api/v2/events` is SSE of StreamFrame JSON with Last-Event-ID carrying the
opaque cursor; filters follow EventTailRequest. Before streaming, apply the
same human auth and limits as the socket. Reauthentication/expiry closes the
stream explicitly. Human controls use POST RPC `lane.stop,lane.resume,
lane.mark,mail.send`, fresh proof and normal service validators. Mark merged/
abandoned is a state decision, never a fabricated Git merge.

Decision views include actual text/source/version and relevance/recency.
Raw views preserve both vendors' captured bytes/mail across all levels and
show gaps/replacements; render all data as inert escaped text. Tree distinguishes
configured instances from launched lives and uses actual starter edges,
including L5→L3. Refusal counts distinguish refusals, warnings, unscored,
critical-unscored and unknown capture; unavailable inventory is an error, not
an empty successful list. Plugins distinguish declared versus verified loading.
Resource views include exact source/hash/version and approval/application history.
Lifecycle must converge to committed service events within two seconds under
the defined healthy load.

D7 relationships use immutable lives: same level **and same direct parent**
for peers; any lower descendant for downward messaging; only the direct starter
for upward reporting. Recheck on enqueue and delivery. Level/common root alone
does not authorize peers. Human mail may target any level, including L3,
with source dashboard/CLI derived by the endpoint and actor human.
Only L5/L6 may send to a human through an exact current granted org channel.
No missing-parent/channel fallback for L3/L4 and no upward skips.

Mail is screened immutable file content, at most 256 KiB, with IDs/hash,
sender/recipient, source, ask/reply linkage, sequence and logical-turn receipts.
Statuses are `queued,delivering,delivered,returned,answered`; delivery/return retains
prompt status and cause. A profile-limit run cannot acknowledge or return mail
solely due to its process exit. Channel delivery uses durable outbox receipts,
records partial failures, and retries never duplicate a confirmed successful
external send. Report artifacts live outside the task Git tree. Browsing,
briefing and receiving mail never execute embedded content.
Only the service sets `answered`, after a DecisionAnswer commit authorized by
verified human proof or D6; the original question and send history remain intact.

## 10. Remaining port, installation and compatibility contracts

Records collections are `decisions,observations,ledger,refusals,tools,reports,
archives,judge_egress,embeddings`. Read APIs return screened, scope-filtered
records and provenance. Search mode is `keyword|vector|hybrid`. A lane can
append observations and reports, including inert decision proposals, never
canonical decisions or service/lifecycle/approval/ledger provenance. Refusal/tool reports are observations
unless independently captured; a submitted “passed” text cannot be a trusted
check receipt. Decisions mutate actions are `add,supersede,annotate,feedback,
embed`; canonical mutation requires a verified human operation proof; L6 uses
the approved exact D6 resource transaction. Supersede/annotate/feedback require
a visible canonical record and CAS. Annotation/feedback retain the original
content and append separate blob references; they cannot replace the decision
text with a note. Authoring a decision does not grant authority. Imports/exports
use manifests and confined parsers; no `--db` host path reaches the service.

Box providers are `aws|gcp`. BoxSpec uses schema `laneboss.box-spec.v2`;
WorkerPlan uses `laneboss.worker-plan.v2` and kind `test|import|export|archive|
render|box_run|channel|owner_sheet|gateway`. The named resource grant resolves provider/account ceiling,
region/image constraints, verified transport and cost budget. Purpose starts
with `lb-`; one active disposable test machine per authorized lane.
WorkerPlan argv is ordinary unprivileged work **inside** the job's grants,
never a root helper or service command. Input source hashes, real exits, harvest
hash/read-back and collection receipts survive spot loss. Actual paid provisioning
and secrets require the future lane's brief; this freeze performs none.

MigrationManifest uses `laneboss.migration.v2` and keeps original inventory,
quiescence/verification receipts, source version/protocol/revision. Support
0.7.0 and 1.0.0-candidate inputs, retained protocol-1.1.0/1.2.0 history, and the
documented 0.5.0 incompatible rollback boundary. Freeze old dispatch/writers,
verify a protected copy, import into new service-owned storage and keep exact
event IDs/sequences/bytes/hashes as historical origin. Never infer active
identity/parenthood from copied labels. Preserve decisions, embeddings, mail,
owner queue, archives, refusal/raw records and original protocol bytes;
delivered mail is not sent again. An incomplete/corrupt source stops import
without modifying it. Unfinished work imports selected private history/data
through a confined worker and relaunches under a new verified life.

Upgrade uses a human-approved immutable ReleaseManifest, all OS/arch artifact
digests, vendor pin and source hash. Quiesce dispatch/watchdog and active affected
runs, drain capture/effects, verify frozen backup and recovery procedure, then
stage coherent service/helper/inside-client bytes and schema migration. Any
canonical org-source changes additionally use D6. Old executable bytes stay
until their processes end. Rollback restores the matched old binary plus its
frozen compatible state/config, after retaining new history/work; it cannot
relink an old binary onto a new store.

Administrator installer owns only its dedicated accounts, immutable binary
binding, service/helper units, bwrap profile and resource leases. It records
before/after and recovery; it never turns off host-wide security or signs into
vendors. Ordinary installer retains checksummed companion choice and explicit
upgrade/opt-out. Documentation must execute actual source/supplied-binary guide
blocks on a disposable Linux box. Native Darwin is advertised only for its
proved cells; WSL2/Windows are later roadmap work and cannot be claimed from
Linux compilation.

The old hook protection engine is deleted only after the exact release
OS/service boundary rows pass with hook absent/allow and vendor inner sandbox
disabled, then pass again after deletion. Delete isolation.md §7's named
prediction code, its bypasses and protection-only tests; retain adversarial
inputs as executed syscall fixtures and blacklist policy as policy.
No green semantic verdict, fake syscall result or successful vendor exit
substitutes for these rows.

## 11. JSON shape appendix (normative)

Objects below are exact JSON field maps; `?` means an optional omitted field,
never null. `[]T` is an array, `bytes` is canonical padded RFC4648 base64,
and `[N]T` is an exact-length array of N recursively validated elements.
`integer` follows the exact range above, `number` is a finite JSON number.
ID, Digest, Timestamp, Driver, Method and EventKind are strings with the constraints
above. All other names reference another row. This is synchronized with the
exported Go types in `internal/v2/api`; `json:"-"` internal fields are excluded.
For empty administrative event relationships, omit optional life/run/parent/root
fields; starter_chain is [] and starter_event_seq is 0. Empty is exactly {}.
Go interfaces and worker-only non-JSON types are in `api/interfaces.go` and
`api/peer.go`, with concrete typed failing stubs in every named component.

Additional field rules: backend is `linux-bwrap-landlock|darwin-seatbelt`;
NetworkGrant.mode is `internet|service|publish` (empty network grants mean
offline). The default root template proposes an explicit public-Internet grant;
a child selects it through the parent like any other capability. ResourceGrant
bounds provider/regions/images/machine types/concurrency/hourly and total cost;
it is separate from task-secret injection. These are resource scopes, never
command permission lists. CredentialSlot.mode is `claudock-headless,claude-api-key,
claudock-helper,claudock-api,codex-file,codex-api,codex-local`, each unavailable
until its pinned adapter mode passes. Capture stream is `stdout|stderr|vendor`;
coverage is `complete|partial|unsupported|missing`.
ConfigReadRequest.view is `list|show|path|settings|roles|channels|plugins`;
path returns logical endpoint/projection metadata, never a writable state path.
Trigger.kind is `start|adopt|manual|mail|loop|profile_limit`.
AdoptRequest.import_manifest references AdoptionManifest with
`schema:"laneboss.adoption.v2"`, selected data/history and real quiescence
evidence; its role/task/grants are newly checked, not copied authority.
Budget limits are finite nonnegative ceilings; zero spend permits only
credential-free/no-cost operations, zero wall/process/memory/disk is invalid
for a launch. Opaque reasons/notices are screened explanatory strings.


### approval.go

Source: [api/approval.go](../../internal/v2/api/approval.go).

| Object | JSON field map |
| --- | --- |
| `ChangeApplyRequest` | `{change_id: ID, approval_id: ID, expected_generation: integer}` |
| `ChangeApproval` | `{id: ID, change_id: ID, requester_life_id: ID, approver_key_id: ID, manifest_sha256: Digest, base_generation: integer, nonce_id: ID, approved_at: Timestamp, expires_at: Timestamp, simulated_presence?: boolean}` |
| `ChangeApproveRequest` | `{change_id: ID, manifest_sha256: Digest, base_generation: integer}` |
| `ChangeGetRequest` | `{change_id: ID}` |
| `ChangeProposeRequest` | `{org_id: ID, base_generation: integer, files: []ResourceDelta, reason: BlobRef}` |
| `ChangeReceipt` | `{id: ID, change_id: ID, approval_id: ID, old_generation: integer, new_generation: integer, manifest_sha256: Digest, applied_at: Timestamp, simulated_presence?: boolean}` |
| `ChangeRequest` | `{config: string, reason: BlobRef, source_snapshot: OrgSnapshotRef, ownership_manifest: BlobRef, id: ID, org_id: ID, requester: Actor, base_generation: integer, files: []ResourceDelta, derived: []ResourceDelta, manifest_sha256: Digest, diff: BlobRef, renderer: Executable, status: string, created_at: Timestamp, expires_at: Timestamp}` |
| `ResourceDelta` | `{path: string, action: string, mode: integer, before_sha256?: Digest, after?: BlobRef}` |

### base.go

Source: [api/base.go](../../internal/v2/api/base.go).

| Object | JSON field map |
| --- | --- |
| `Empty` | `{}` |
| `Error` | `{code: ErrorCode, message: string, instead: string, retryable: boolean, operation_id?: ID, owner?: string}` |
| `Request` | `{protocol: string, schema: integer, config: string, request_id: ID, idempotency_key: ID, request_sha256: Digest, method: Method, params: json.RawMessage, proof?: ProofRef}` |
| `Response` | `{protocol: string, schema: integer, request_id: ID, last_seq: integer, result?: json.RawMessage, error?: Error}` |
| `StreamFrame` | `{request_id: ID, index: integer, cursor: string, event?: Event, chunk?: BlobChunk, end: boolean, error?: Error}` |

### common.go

Source: [api/common.go](../../internal/v2/api/common.go).

| Object | JSON field map |
| --- | --- |
| `Actor` | `{kind: string, id: ID, life_id?: ID, level?: integer, role?: string}` |
| `BlobBeginRequest` | `{class: string, bytes: integer, sha256: Digest}` |
| `BlobChunk` | `{object_id: ID, offset: integer, data: bytes, sha256: Digest}` |
| `BlobCommitRequest` | `{object_id: ID, sha256: Digest}` |
| `BlobReadRequest` | `{object_id: ID, offset: integer, limit: integer}` |
| `BlobRef` | `{id: ID, sha256: Digest, bytes: integer, class: string}` |
| `BlobUpload` | `{object_id: ID, max_chunk_bytes: integer, expires_at: Timestamp}` |
| `Budget` | `{wall_ms: integer, cpu_seconds: integer, memory_bytes: integer, processes: integer, disk_bytes: integer, spend_micros: integer, currency: string}` |
| `Capability` | `{name: string, available: boolean, reason: string, evidence?: BlobRef}` |
| `CursorRequest` | `{cursor: string, limit: integer}` |
| `Health` | `{protocol: string, schema: integer, service_version: string, artifact_sha256: Digest, ready: boolean, capabilities: []Capability}` |
| `HealthRequest` | `{client_version: string, artifact_sha256: Digest}` |
| `LifeRef` | `{life_id: ID, run: integer}` |
| `ListRequest` | `{life_id?: ID, cursor: string, limit: integer}` |
| `Operation` | `{id: ID, status: string, life_id?: ID, run?: integer, first_seq: integer, last_seq: integer, result?: BlobRef, error?: Error, simulated_presence?: boolean}` |
| `OperationGetRequest` | `{operation_id: ID}` |
| `ProofRef` | `{id: ID, request_sha256: Digest, expires_at: Timestamp, simulated_presence?: boolean}` |
| `Scope` | `{config: string, actor: Actor, launch_id?: ID, endpoint_generation: integer, policy_generation: integer}` |

### events.go

Source: [api/events.go](../../internal/v2/api/events.go).

| Object | JSON field map |
| --- | --- |
| `ChangeEvent` | `{change: ChangeRequest, approval?: ChangeApproval, receipt?: ChangeReceipt, reason: string}` |
| `CleanEvent` | `{archive_receipt: ArchiveReceipt, removed_object_ids: []ID, retained_object_ids: []ID, quiescence: ProcessObservation}` |
| `CredentialEvent` | `{slot: CredentialSlot, outcome: string}` |
| `Event` | `{schema: integer, id: ID, config: string, seq: integer, kind: EventKind, actor: Actor, requested_by: Actor, request_id: ID, operation_id: ID, life_id?: ID, run?: integer, logical_turn_id?: ID, parent_life_id?: ID, root_life_id?: ID, starter_chain: []ID, starter_event_seq: integer, recorded_at: Timestamp, requested_at: Timestamp, observed_at: Timestamp, origin: string, payload: json.RawMessage}` |
| `GrantEvent` | `{grant_set: GrantSet, reason?: BlobRef}` |
| `LaunchEvent` | `{task: BlobRef, launch_id: ID, lane: Lane, grant_set_id: ID, grants_sha256: Digest, policy_generation: integer, prompt_template: TemplateRef, task_sha256: Digest, prompt: BlobRef, boundary_backend: string, endpoint_generation: integer, task_secret_names: []string, task_secret_file_names: []string, secret_grant_ids: []ID, secret_source_versions: []string, injection_outcome: string, trigger: Trigger, profile_continuation_of?: integer, profile_swap?: ProfileSwap}` |
| `LaunchFailedEvent` | `{launch_id: ID, stage: string, error: Error, agent_executed: boolean}` |
| `MigrationEvent` | `{plan: MigrationPlan, manifest: BlobRef, legacy_event_count: integer}` |
| `OperationEvent` | `{operation: Operation, request_sha256: Digest}` |
| `RunEndEvent` | `{launch_id: ID, reason: string, observation: ProcessObservation, profile_continuation: boolean, budget_remaining: Budget}` |
| `SecretEvent` | `{names: []string, versions: []string, grant_ids: []ID, outcome: string, key_id?: ID}` |
| `ServiceEvent` | `{version: string, artifact_sha256: Digest, recovered_operations: []ID}` |
| `StateEvent` | `{from: string, to: string, generation: integer, review_id?: ID, reason?: BlobRef}` |
| `TurnEvent` | `{task: BlobRef, trigger: Trigger, prompt: BlobRef, status: string, mail_ids: []ID}` |
| `WatchdogEvent` | `{signal?: LimitSignal, swap?: ProfileSwap, reason: string, retry_after_ms: integer, budget_remaining: Budget}` |
| `WorkerEvent` | `{worker_id: ID, kind: string, input: BlobRef, output?: BlobRef, status: string, error?: Error}` |

### grants.go

Source: [api/grants.go](../../internal/v2/api/grants.go).

| Object | JSON field map |
| --- | --- |
| `ChannelDelegation` | `{parent_grant_id: ID, channel_id: ID, delegate: boolean, expires_at: Timestamp}` |
| `ChannelGrant` | `{id: ID, parent_grant_id?: ID, channel_id: ID, delegate: boolean, expires_at: Timestamp}` |
| `DataGrant` | `{id: ID, parent_grant_id?: ID, source_object_id: ID, source_sha256: Digest, relative_path: string, access: string, delivery: string, destination: string, delegate: boolean, expires_at: Timestamp, publication_id?: ID, history_scope: string}` |
| `DataGrantRequest` | `{parent_grant_id: ID, relative_path: string, access: string, delivery: string, destination: string, delegate: boolean, expires_at: Timestamp, publication_id?: ID}` |
| `GrantGetRequest` | `{grant_set_id: ID}` |
| `GrantRequest` | `{resources: []ResourceDelegation, data: []DataGrantRequest, secrets: []SecretDelegation, profiles: []ProfileDelegation, network: []NetworkDelegation, channels: []ChannelDelegation}` |
| `GrantRevokeRequest` | `{grant_set_id: ID, expected_generation: integer, reason: BlobRef}` |
| `GrantSet` | `{resources: []ResourceGrant, id: ID, life_id: ID, parent_life_id?: ID, sha256: Digest, policy_generation: integer, generation: integer, data: []DataGrant, secrets: []SecretGrant, profiles: []ProfileGrant, network: []NetworkGrant, channels: []ChannelGrant, expires_at: Timestamp, revoked: boolean}` |
| `GrantValidateRequest` | `{parent_life_id: ID, child_level: integer, requested: GrantRequest, expected_policy_generation: integer}` |
| `GrantValidation` | `{effective: GrantSet, warnings: []string}` |
| `Materialization` | `{grant_set_id: ID, manifest: BlobRef, objects: []MaterializedObject}` |
| `MaterializedObject` | `{grant_id: ID, source_identity: string, destination_identity: string, snapshot_sha256: Digest, workspace_id: ID}` |
| `NetworkDelegation` | `{parent_grant_id: ID, endpoint_id: ID, delegate: boolean, expires_at: Timestamp}` |
| `NetworkGrant` | `{id: ID, parent_grant_id?: ID, endpoint_id: ID, mode: string, delegate: boolean, expires_at: Timestamp}` |
| `ProfileDelegation` | `{parent_grant_id: ID, profile_id: ID, delegate: boolean, expires_at: Timestamp}` |
| `ProfileGrant` | `{id: ID, parent_grant_id?: ID, profile_id: ID, driver: Driver, provider: string, paid: boolean, delegate: boolean, expires_at: Timestamp}` |
| `ResourceDelegation` | `{parent_grant_id: ID, regions: []string, image_ids: []string, machine_types: []string, max_active: integer, max_hourly_micros: integer, total_budget_micros: integer, delegate: boolean, expires_at: Timestamp}` |
| `ResourceGrant` | `{id: ID, parent_grant_id?: ID, source_handle: ID, provider: string, regions: []string, image_ids: []string, machine_types: []string, max_active: integer, max_hourly_micros: integer, total_budget_micros: integer, delegate: boolean, expires_at: Timestamp}` |
| `RootGrantRequest` | `{manifest: BlobRef, budget: Budget}` |
| `SecretDelegation` | `{parent_grant_id: ID, name: string, version: string, delivery: string, target: string, delegate: boolean, expires_at: Timestamp}` |
| `SecretGrant` | `{id: ID, parent_grant_id?: ID, name: string, source_handle: ID, version: string, delivery: string, target: string, delegate: boolean, expires_at: Timestamp}` |
| `TestChildRequest` | `{child: LifeRef, candidate: BlobRef, test_plan: BlobRef, budget: Budget}` |

### identity.go

Source: [api/identity.go](../../internal/v2/api/identity.go).

| Object | JSON field map |
| --- | --- |
| `HumanChallenge` | `{id: ID, challenge: bytes, config: string, method: Method, target_id: ID, request_sha256: Digest, base_generation: integer, origin: string, rp_id: string, expires_at: Timestamp}` |
| `HumanChallengeRequest` | `{method: Method, target_id: ID, request_sha256: Digest, base_generation: integer}` |
| `HumanConfirmRequest` | `{challenge_id: ID, credential_id: ID, client_data_json: bytes, authenticator_data: bytes, signature: bytes}` |
| `HumanSession` | `{id: ID, expires_at: Timestamp, idle_expires_at: Timestamp, config: string, simulated_presence?: boolean}` |
| `HumanSessionRequest` | `{}` |
| `Ticket` | `{principal_id: ID, config: string, endpoint_generation: integer, id: ID, level: integer, role: string, grant_set_id: ID, expires_at: Timestamp, redeemed: boolean, simulated_presence?: boolean}` |
| `TicketIssueRequest` | `{level: integer, role: string, grant_set_id: ID, expires_at: Timestamp}` |

### lifecycle.go

Source: [api/lifecycle.go](../../internal/v2/api/lifecycle.go).

| Object | JSON field map |
| --- | --- |
| `AdoptRequest` | `{profile_grant_id: ID, model: string, effort: string, task: BlobRef, root_ticket_id?: ID, lane: string, level: integer, role: string, import_manifest: BlobRef, grants: GrantRequest, driver: Driver, budget: Budget, expected_policy_generation: integer}` |
| `ArchiveReceipt` | `{id: ID, life_id: ID, manifest: BlobRef, archive_sha256: Digest, read_back_sha256: Digest, verified_at: Timestamp, store_id: ID}` |
| `ArchiveRequest` | `{target: LifeRef, expected_generation: integer}` |
| `AttachInputRequest` | `{target: LifeRef, channel_id: ID, input: bytes, columns: integer, rows: integer}` |
| `AttachRequest` | `{target: LifeRef, cursor: string, mode: string}` |
| `CleanRequest` | `{target: LifeRef, expected_generation: integer, archive_receipt_id: ID}` |
| `EventPage` | `{events: []Event, cursor: string, complete: boolean}` |
| `EventTailRequest` | `{life_id: ID, run: integer, since: integer, cursor: string, follow: boolean, until: EventKind, deadline_ms: integer}` |
| `Lane` | `{task: BlobRef, launch_id: ID, cancellation_epoch: integer, counters: TaskCounters, profile_grant_id: ID, model: string, effort: string, budget_remaining: Budget, life_id: ID, name: string, parent_life_id?: ID, root_life_id: ID, starter_chain: []ID, starter_event_seq: integer, level: integer, role: string, state: string, generation: integer, run: integer, logical_turn_id?: ID, session: Session, workspace: Workspace, grant_set_id: ID, policy_generation: integer, cleaned: boolean, containment: string, last_seq: integer}` |
| `LanePage` | `{lanes: []Lane, cursor: string}` |
| `LoopRequest` | `{target: LifeRef, expected_generation: integer, enabled: boolean, idle_message?: BlobRef, backoff_ms: integer}` |
| `MarkRequest` | `{target: LifeRef, expected_generation: integer, state: string, review: ReviewReceipt}` |
| `ResumeRequest` | `{target: LifeRef, expected_generation: integer, message: BlobRef, budget: Budget}` |
| `ReviewReceipt` | `{id: ID, reviewer: Actor, diff: BlobRef, checks: []BlobRef, record_inventory: BlobRef, refusal_resolution: []ID, coverage: string, evidence?: ReviewEvidence}`; evidence is required for new live acceptance. |
| `ReviewRequest` | `{target: LifeRef, diff: BlobRef, checks: []BlobRef, record_inventory: BlobRef, refusal_resolution: []ID}` |
| `StartRequest` | `{lane: string, project_id: ID, level: integer, role: string, task: BlobRef, grants: GrantRequest, driver: Driver, profile_grant_id: ID, model: string, effort: string, budget: Budget, root_ticket_id?: ID, expected_policy_generation: integer}` |
| `StopRequest` | `{target: LifeRef, expected_generation: integer, reason: BlobRef}` |
| `TemplateRef` | `{id: ID, source_sha256: Digest, generation: integer, rendered_sha256: Digest}` |
| `Trigger` | `{kind: string, mail_ids: []ID, causing_seqs: []integer, causing_run?: integer}` |
| `TurnRequest` | `{target: LifeRef, expected_generation: integer, mail_ids: []ID, idle_message?: BlobRef, budget: Budget}` |
| `Workspace` | `{id: ID, project_id: ID, base: string, branch: string, logical_cwd: string, snapshot: BlobRef}` |

### mail.go

Source: [api/mail.go](../../internal/v2/api/mail.go).

| Object | JSON field map |
| --- | --- |
| `Delivery` | `{id: ID, mail_id: ID, channel_id: ID, status: string, remote_receipt_id?: string, error?: Error, evidence?: ChannelSendEvidence}`; evidence is required for new confirmed channel delivery. |
| `Mail` | `{generation: integer, artifacts: []BlobRef, answer?: DecisionAnswer, id: ID, sender: Actor, recipient_life_id?: ID, channel_grant_id?: ID, content: BlobRef, source: string, queued_seq: integer, logical_turn_id?: ID, status: string, ask: boolean, reply_to?: ID}` |
| `MailPage` | `{messages: []Mail, cursor: string}` |
| `MailReceipt` | `{mail_id: ID, target: LifeRef, logical_turn_id: ID, status: string, prompt_status: string, cause: string, observed_at: Timestamp}` |
| `MailSendRequest` | `{recipient_life_id: ID, channel_grant_id?: ID, content: BlobRef, ask: boolean, reply_to?: ID}` |
| `ReportRequest` | `{ask: boolean, content: BlobRef, artifacts: []BlobRef, channel_grant_id?: ID, reply_to?: ID}` |

### manifests.go

Source: [api/manifests.go](../../internal/v2/api/manifests.go).

| Object | JSON field map |
| --- | --- |
| `AdoptionManifest` | `{schema: string, workspace: Workspace, session: Session, private_history: BlobRef, quiescence: BlobRef, source_version: string}` |
| `BoxSpec` | `{schema: string, region: string, image_id: string, machine_type: string, architecture: string, max_hourly_micros: integer, disk_bytes: integer}` |
| `MigrationManifest` | `{schema: string, source_version: string, source_protocol: string, source_revision: string, inventory: ObjectManifest, quiescence: BlobRef, verification: BlobRef}` |
| `ObjectEntry` | `{assembly?: ObjectAssembly, path: string, kind: string, mode: integer, content?: BlobRef, link_target?: string}` |
| `ObjectManifest` | `{schema: string, entries: []ObjectEntry}` |
| `RootGrantManifest` | `{resources: []ResourceGrant, schema: string, data: []DataGrant, secrets: []SecretGrant, profiles: []ProfileGrant, network: []NetworkGrant, channels: []ChannelGrant}` |
| `WorkerPlan` | `{schema: string, kind: string, executable: Executable, argv: []string, input: BlobRef, grant_set_id: ID, budget: Budget}` |

### policy.go

Source: [api/policy.go](../../internal/v2/api/policy.go).

| Object | JSON field map |
| --- | --- |
| `Briefing` | `{markdown: BlobRef, template: TemplateRef, policy_generation: integer, sources: []SourceRef, checks: []Capability, lane_groups: LaneGroups}` |
| `BriefingRequest` | `{role: string, level: integer, life_id?: ID}` |
| `CommandData` | `{tool: string, command: bytes, argv: []string, declared_paths: []string, cwd: string, raw_sha256: Digest}` |
| `ConfigReadRequest` | `{view: string, context?: RoleContext}` |
| `ConfigView` | `{generation: integer, sources: []SourceRef, projection: BlobRef, warnings: []string}` |
| `DecisionCandidate` | `{authority: DecisionAuthority, applies_to: DecisionApplicability, id: ID, text: string, source: SourceRef, effective_at: Timestamp, binding: boolean}` |
| `EffectivePolicy` | `{guidance_min_relevance: number, guidance_source: SourceRef, profile_exclusions: []ID, generation: integer, sha256: Digest, context: RoleContext, rules: []Rule, skip: []SkipEntry, sources: []SourceRef, judge: JudgeConfig, guidance_half_life_seconds: integer, allow_capture_refusal?: boolean, capture_refusal_approval_id?: ID}`; capture refusal defaults to false and requires current D6 approval. |
| `Guidance` | `{target: LifeRef, task: BlobRef, policy_generation: integer, candidate_snapshot_id: ID, reservation_id: ID, judgment_ids: []ID, id: ID, logical_turn_id: ID, as_of: Timestamp, items: []GuidanceItem, weighted_score?: number, judgment_id?: ID, status: string, notice: string}` |
| `GuidanceItem` | `{decision_id: ID, source: SourceRef, probability?: number, age_seconds: integer, weight: number, score?: number, binding: boolean}` |
| `GuidanceRequest` | `{target: LifeRef, logical_turn_id: ID, task: BlobRef}` |
| `JudgeConfig` | `{provider: string, model: string, deployment_sha256: Digest, tokenizer_sha256: Digest, context_tokens: integer, max_bytes: integer, max_questions: integer, command_deadline_ms: integer, guidance_deadline_ms: integer, cache_ttl_ms: integer, outage_policy: string}` |
| `JudgeContext` | `{config: string, target: LifeRef, role: RoleContext, logical_turn_id: ID, grant_set_id: ID, grants_sha256: Digest, policy_generation: integer, cwd: string}` |
| `JudgeReply` | `{request?: BlobRef, batch_ids?: []ID, id: ID, status: string, results: []Judgment, selected_model: string, reported_model: string, deployment_sha256: Digest, latency_ms: integer, input_bytes: integer, input_tokens: integer, cost_micros: integer, raw?: BlobRef, unavailable_reason: string}` |
| `JudgeRequest` | `{id: ID, purpose: string, rules: []JudgeRule, command?: CommandData, decisions: []DecisionCandidate, context: JudgeContext, task: bytes, config: JudgeConfig, deadline_ms: integer, max_cost_micros: integer}` |
| `JudgeRule` | `{id: ID, text: string, source_sha256: Digest, criteria_version: string}` |
| `Judgment` | `{question_id: ID, status: string, probability?: number, reason: string}` |
| `LaneGroups` | `{running: []ID, ended: []ID, accepted: []ID, lost: []ID, idle: []ID, others: []ID}` |
| `OrgValidateRequest` | `{generation: integer}` |
| `OrgValidation` | `{valid: boolean, problems: []string}` |
| `PolicyDecision` | `{id: ID, result: string, rules: []RuleDecision, policy_generation: integer, input: BlobRef, cache_of?: ID, skip_id?: ID, latency_ms: integer, audit_complete: boolean}` |
| `PolicyEvaluateRequest` | `{target: LifeRef, logical_turn_id: ID, command: CommandData}` |
| `PolicyGetRequest` | `{life_id: ID}` |
| `RoleContext` | `{level: integer, role: string, instance_id?: ID}` |
| `Rule` | `{id: ID, text: string, instead: string, band: string, critical: boolean, scope: RuleScope, source: SourceRef, thresholds: Thresholds}` |
| `RuleDecision` | `{rule_id: ID, result: string, probability?: number, critical: boolean, thresholds: Thresholds, reason: string, instead: string, judgment_id?: ID}` |
| `RuleScope` | `{levels: []integer, roles: []string}` |
| `SkipEntry` | `{id: ID, description: string, rule_set_sha256: Digest, context_sha256: Digest, source: SourceRef}` |
| `SourceRef` | `{id: ID, path: string, sha256: Digest, generation: integer}` |
| `TemplateRequest` | `{context: RoleContext, task: BlobRef, grant_set_id: ID}` |
| `Thresholds` | `{match: number, uncertain_low: number, uncertain_high: number, calibration_id: ID}` |

### ports.go

Source: [api/ports.go](../../internal/v2/api/ports.go).

| Object | JSON field map |
| --- | --- |
| `BootstrapRequest` | `{org_name: string, source_manifest: BlobRef}` |
| `Box` | `{id: ID, provider: string, state: string, generation: integer, resource_grant_id: ID, cost_micros: integer, evidence: []BlobRef}` |
| `BoxControlRequest` | `{box_id: ID, expected_generation: integer}` |
| `BoxLaunchRequest` | `{provider: string, resource_grant_id: ID, purpose: string, spec: BlobRef, budget: Budget}` |
| `BoxPage` | `{boxes: []Box, cursor: string}` |
| `BoxRunRequest` | `{box_id: ID, source: BlobRef, plan: BlobRef, expected_generation: integer}` |
| `DecisionMutateRequest` | `{action: string, record_id?: ID, content: BlobRef, expected_generation: integer}` |
| `MigrationApplyRequest` | `{plan_id: ID}` |
| `MigrationPlan` | `{id: ID, source_version: string, source_manifest: BlobRef, target_schema: integer, changes: []string, problems: []string, requires_relaunch: []ID}` |
| `MigrationPlanRequest` | `{source_version: string, source_manifest: BlobRef}` |
| `RebuildRequest` | `{frozen_snapshot: BlobRef}` |
| `Record` | `{id: ID, collection: string, life_id?: ID, run?: integer, content: BlobRef, actor: Actor, origin: string, recorded_at: Timestamp, generation: integer, related_ids?: []ID, action?: string, annotations?: []BlobRef, feedback?: []BlobRef}` |
| `RecordAppendRequest` | `{collection: string, content: BlobRef, related_ids: []ID}` |
| `RecordGetRequest` | `{record_id: ID}` |
| `RecordPage` | `{records: []Record, cursor: string}` |
| `RecordQuery` | `{record_id?: ID, collection: string, life_id?: ID, query: string, search_mode: string, cursor: string, limit: integer}` |
| `ReleaseArtifact` | `{os: string, arch: string, sha256: Digest, bytes: integer}` |
| `ReleaseManifest` | `{version: string, protocol: string, schema: integer, artifacts: []ReleaseArtifact, source_sha256: Digest, vendor_manifest: BlobRef}` |
| `SecretKey` | `{id: ID, algorithm: string, public_key: bytes, expires_at: Timestamp}` |
| `SecretList` | `{secrets: []SecretInfo}` |
| `SecretStage` | `{id: ID, name: string, version: string, expires_at: Timestamp}` |
| `SecretStageRequest` | `{key_id: ID, name: string, version: string, ephemeral_public_key: bytes, nonce: bytes, ciphertext: bytes}` |
| `TransferRequest` | `{collection: string, manifest: BlobRef, expected_generation: integer}` |
| `UpgradeApplyRequest` | `{plan_id: ID}` |
| `UpgradePlan` | `{id: ID, release: ReleaseManifest, frozen_backup?: BlobRef, quiescent: boolean, problems: []string}` |
| `UpgradePlanRequest` | `{release: ReleaseManifest}` |
| `Verification` | `{ok: boolean, objects: integer, events: integer, problems: []string, manifest?: BlobRef}` |
| `VerifyRequest` | `{scope: string, object_id?: ID}` |

### runtime.go

Source: [api/runtime.go](../../internal/v2/api/runtime.go).

| Object | JSON field map |
| --- | --- |
| `CaptureRecord` | `{binding_id?: ID, id: ID, target: LifeRef, stream: string, offset: integer, data: BlobRef, observed_at: Timestamp, primary: boolean, coverage: string, replacement_of?: ID}` |
| `CredentialSlot` | `{id: ID, profile_grant_id: ID, profile_id: ID, mode: string, lease_id: ID, expires_at: Timestamp}` |
| `Executable` | `{id: ID, sha256: Digest, version: string}` |
| `HelperLaunchRequest` | `{cause: InternalIntent, lease_id: ID, prepared_spec_id: ID, spec_sha256: Digest}` |
| `HelperLease` | `{id: ID, uid: integer, gid: integer, containment_id: ID, endpoint_generation: integer}` |
| `HelperLeaseRequest` | `{reservation_id?: ID, cause: InternalIntent, config: string, life_id: ID, backend: string, budget: Budget, runtime_manifest_id: ID}`; reservation_id is required for agent allocation. |
| `Injection` | `{target: LifeRef, slot_ids: []ID, task_secret_names: []string, task_secret_file_names: []string, grant_ids: []ID, source_versions: []string, outcome: string}` |
| `IsolationCapabilities` | `{backend: string, available: boolean, kernel: string, landlock_abi: integer, checks: []Capability}` |
| `LaunchPermit` | `{launch_id: ID, prepared_id: ID, record_sha256: Digest, committed_seq: integer}` |
| `LaunchRecord` | `{kind?: string, id: ID, config: string, target: LifeRef, parent_life_id?: ID, root_life_id: ID, starter_chain: []ID, starter_event_seq: integer, actor: Actor, uid_lease_id: ID, host_uid: integer, process_generation: string, containment_id: ID, grant_set_id: ID, grants_sha256: Digest, policy_generation: integer, endpoint_generation: integer, revoked: boolean}`; new bindings require kind agent or worker. |
| `LaunchSpec` | `{plan_id?: ID, capture?: CaptureBinding, kind: string, worker?: WorkerPlan, id: ID, target: LifeRef, launch_id: ID, backend: string, uid_lease_id: ID, workspace: Workspace, materialization: Materialization, grants: GrantSet, runner?: RunnerPlan, injection: Injection, budget: Budget, endpoint_generation: integer, runtime_manifest: BlobRef, policy_generation: integer}`; plan_id/capture are required for every new agent spec. |
| `LimitSignal` | `{target: LifeRef, kind: string, profile_id: ID, provider: string, capture_id: ID, capture_sha256: Digest, exit_code?: integer, adapter_version: string, observed_at: Timestamp, usage_evidence?: BlobRef}`; new Claudock quota signals require verified outside usage evidence. |
| `PreparedLaunch` | `{id: ID, spec_sha256: Digest, target: LifeRef, containment_id: ID, process_generation: string, endpoint_generation: integer, gate_id: ID}` |
| `PrivateHome` | `{id: ID, workspace_id: ID, vendor_directory: string, history_id: ID}` |
| `ProcessHandle` | `{id: ID, target: LifeRef, containment_id: ID, generation: string}` |
| `ProcessObservation` | `{handle: ProcessHandle, state: string, exit_code?: integer, signal?: integer, survivors?: integer, prompt_status: string, observed_at: Timestamp}` |
| `ProfileSwap` | `{profile_grant_id: ID, eligibility_id: ID, expected_generation: integer, cancellation_epoch: integer, from_profile_id: ID, to_profile_id: ID, causing_run: integer, continuation_run: integer, logical_turn_id: ID, limit: LimitSignal, room: Room, operation_id: ID}` |
| `Room` | `{profile_id: ID, available: boolean, checked_at: Timestamp, expires_at: Timestamp, evidence: BlobRef, reason: string}` |
| `RunnerPlan` | `{driver: Driver, executable: Executable, argv: []string, cwd: string, environment_names: []string, prompt: BlobRef, home: PrivateHome, slot: CredentialSlot, session: Session, inner_sandbox: string, adapter_version: string}` |
| `RunnerRequest` | `{target: LifeRef, logical_turn_id: ID, session: Session, prompt: BlobRef, home: PrivateHome, slot: CredentialSlot, executable: Executable, model: string, effort: string, budget: Budget}` |
| `SecretImportRequest` | `{name: string, version: string, sealed_upload_id: ID}` |
| `SecretInfo` | `{name: string, version: string, source_handle: ID, key_id: ID, revoked: boolean}` |
| `SecretRevokeRequest` | `{name: string, expected_version: string}` |
| `SecretRotateRequest` | `{name: string, expected_version: string, sealed_upload_id: ID}` |
| `Session` | `{history_id: ID, id: ID, driver: Driver, vendor_id: string, vendor_version: string, home_id: ID, logical_cwd: string}` |

### views.go

Source: [api/views.go](../../internal/v2/api/views.go).

| Object | JSON field map |
| --- | --- |
| `ApprovalView` | `{changes: []ChangeRequest, approvals: []ChangeApproval, applications: []ChangeReceipt, cursor: string}` |
| `CaptureGap` | `{binding_id?: ID, target: LifeRef, stream: string, start_offset: integer, end_offset?: integer, reason: string, observed_at: Timestamp}` |
| `DashboardQuery` | `{life_id?: ID, run?: integer, level?: integer, driver?: Driver, since?: Timestamp, until?: Timestamp, cursor: string, limit: integer}` |
| `DecisionView` | `{decisions: []DecisionCandidate, cursor: string}` |
| `RawView` | `{records: []CaptureRecord, messages: []Mail, gaps: []CaptureGap, cursor: string}` |
| `RefusalCount` | `{rule_id: ID, level: integer, refused: integer, warned: integer, unscored: integer, critical_unscored: integer, unknown_coverage: boolean}` |
| `RefusalView` | `{counts: []RefusalCount, receipts: []ID, cursor: string}` |
| `Resource` | `{id: ID, kind: string, path: string, version: string, sha256: Digest, source: BlobRef, approval_id?: ID, declared: boolean, verified_loaded: boolean, observed_at: Timestamp}` |
| `ResourceView` | `{resources: []Resource, generation: integer, cursor: string}` |
| `TreeNode` | `{instance_id?: ID, life_id?: ID, parent_life_id?: ID, level: integer, role: string, state: string, configured: boolean, live: boolean}` |
| `TreeView` | `{nodes: []TreeNode, last_seq: integer, cursor: string}` |

## 12. CLI adapters and acceptance boundary

Every catalog method has a reserved CLI spelling (dots become spaces), plus
legacy intent aliases below. They all require explicit `--config NAME`.
Feature handlers must implement file-backed `--request FILE` for their exact
request body, plus existing ergonomic flags from the legacy help where safe.
They read briefs/messages/grant files locally and upload exact bytes before
referencing BlobRefs. Common envelope/connection/proof processing belongs to
the client/service lane; flag conversion belongs to the named command-file owner.
Unknown flags/subcommands refuse; aliases cannot reintroduce arbitrary argv
forwarding or direct local state. The common dispatcher implements exact
`--request FILE` conversion through the typed socket client. Integration's record
flags upload client-local bounded bytes; no server-side input path is accepted.
Unimplemented feature-specific flags and transport/hosting dependencies continue
to return typed errors. A successful help page is not feature acceptance.

| CLI spelling | RPC / fixed internal entry | Handler owner |
| --- | --- | --- |
| `archive daily` | `lane.archive` | lb-v2-lifecycle |
| `blob begin` | `blob.begin` | lb-v2-service |
| `blob chunk` | `blob.chunk` | lb-v2-service |
| `blob commit` | `blob.commit` | lb-v2-service |
| `blob read` | `blob.read` | lb-v2-service |
| `box` | `box.list` | lb-v2-integrate |
| `box end` | `box.end` | lb-v2-integrate |
| `box harvest` | `box.harvest` | lb-v2-integrate |
| `box launch` | `box.launch` | lb-v2-integrate |
| `box list` | `box.list` | lb-v2-integrate |
| `box run` | `box.run` | lb-v2-integrate |
| `brief render` | `brief.render` | lb-v2-templates |
| `brief start` | `brief.start` | lb-v2-templates |
| `config list` | `config.read` | lb-v2-policy |
| `config path` | `config.read` | lb-v2-policy |
| `config read` | `config.read` | lb-v2-policy |
| `config show` | `config.read` | lb-v2-policy |
| `config validate` | `config.validate` | lb-v2-policy |
| `dashboard` | `dashboard.tree` | lb-v2-dashboard |
| `dashboard approvals` | `dashboard.approvals` | lb-v2-dashboard |
| `dashboard decisions` | `dashboard.decisions` | lb-v2-dashboard |
| `dashboard lifecycle` | `dashboard.lifecycle` | lb-v2-dashboard |
| `dashboard plugins` | `dashboard.plugins` | lb-v2-dashboard |
| `dashboard raw` | `dashboard.raw` | lb-v2-dashboard |
| `dashboard refusals` | `dashboard.refusals` | lb-v2-dashboard |
| `dashboard resources` | `dashboard.resources` | lb-v2-dashboard |
| `dashboard tree` | `dashboard.tree` | lb-v2-dashboard |
| `decisions add` | `decisions.mutate` | lb-v2-integrate |
| `decisions annotate` | `decisions.mutate` | lb-v2-integrate |
| `decisions egress` | `records.query` | lb-v2-integrate |
| `decisions embed` | `decisions.mutate` | lb-v2-integrate |
| `decisions export` | `records.export` | lb-v2-integrate |
| `decisions feedback` | `decisions.mutate` | lb-v2-integrate |
| `decisions get` | `records.get` | lb-v2-integrate |
| `decisions import` | `records.import` | lb-v2-integrate |
| `decisions init` | `records.import` | lb-v2-integrate |
| `decisions load` | `records.import` | lb-v2-integrate |
| `decisions migrate` | `migration.plan` | lb-v2-migration |
| `decisions mutate` | `decisions.mutate` | lb-v2-integrate |
| `decisions search` | `records.query` | lb-v2-integrate |
| `decisions stats` | `records.query` | lb-v2-integrate |
| `decisions supersede` | `decisions.mutate` | lb-v2-integrate |
| `decisions verify` | `store.verify` | lb-v2-service |
| `disk` | `doctor` | lb-v2-admin |
| `doctor` | `doctor` | lb-v2-admin |
| `event append` | `records.append` | lb-v2-integrate |
| `event tail` | `event.tail` | lb-v2-lifecycle |
| `grants get` | `grants.get` | lb-v2-grants |
| `grants revoke` | `grants.revoke` | lb-v2-grants |
| `grants root` | `grants.root` | lb-v2-grants |
| `grants test-child` | `grants.test-child` | lb-v2-grants |
| `grants validate` | `grants.validate` | lb-v2-grants |
| `guidance select` | `guidance.select` | lb-v2-guidance |
| `health` | `health` | lb-v2-service |
| `human challenge` | `human.challenge` | lb-v2-identity |
| `human confirm` | `human.confirm` | lb-v2-identity |
| `human session` | `human.session` | lb-v2-identity |
| `identity self` | `identity.self` | lb-v2-identity |
| `init` | `org.bootstrap` | lb-v2-templates |
| `internal channel` | `internal channel` | lb-v2-messaging |
| `internal credential` | `internal credential` | lb-v2-secrets |
| `internal helper` | `internal helper` | lb-v2-admin |
| `internal judge` | `internal judge` | lb-v2-judge |
| `internal supervisor` | `internal supervisor` | lb-v2-lifecycle |
| `internal worker` | `internal worker` | lb-v2-grants |
| `judge ask` | `judge.ask` | lb-v2-judge |
| `judge egress` | `records.query` | lb-v2-integrate |
| `judge list` | `judge.list` | lb-v2-judge |
| `lane adopt` | `lane.adopt` | lb-v2-lifecycle |
| `lane archive` | `lane.archive` | lb-v2-lifecycle |
| `lane attach` | `lane.attach` | lb-v2-lifecycle |
| `lane check` | `lane.check` | lb-v2-lifecycle |
| `lane clean` | `lane.clean` | lb-v2-lifecycle |
| `lane input` | `lane.input` | lb-v2-lifecycle |
| `lane list` | `lane.list` | lb-v2-lifecycle |
| `lane loop` | `lane.loop` | lb-v2-lifecycle |
| `lane mark` | `lane.mark` | lb-v2-lifecycle |
| `lane refusals` | `records.query` | lb-v2-integrate |
| `lane resume` | `lane.resume` | lb-v2-lifecycle |
| `lane review` | `lane.review` | lb-v2-lifecycle |
| `lane scan` | `records.query` | lb-v2-integrate |
| `lane send` | `mail.send` | lb-v2-messaging |
| `lane start` | `lane.start` | lb-v2-lifecycle |
| `lane status` | `lane.status` | lb-v2-lifecycle |
| `lane stop` | `lane.stop` | lb-v2-lifecycle |
| `lane turn` | `lane.turn` | lb-v2-lifecycle |
| `ledger` | `records.query` | lb-v2-integrate |
| `mail list` | `mail.list` | lb-v2-messaging |
| `mail send` | `mail.send` | lb-v2-messaging |
| `migration apply` | `migration.apply` | lb-v2-migration |
| `migration plan` | `migration.plan` | lb-v2-migration |
| `operation get` | `operation.get` | lb-v2-service |
| `org blacklist list` | `policy.get` | lb-v2-policy |
| `org blacklist try` | `policy.evaluate` | lb-v2-policy |
| `org bootstrap` | `org.bootstrap` | lb-v2-templates |
| `org capture-decision` | `decisions.mutate` | lb-v2-integrate |
| `org change apply` | `org.change.apply` | lb-v2-approval |
| `org change approve` | `org.change.approve` | lb-v2-approval |
| `org change get` | `org.change.get` | lb-v2-approval |
| `org change propose` | `org.change.propose` | lb-v2-approval |
| `org channel add` | `org.change.propose` | lb-v2-approval |
| `org channel read` | `config.read` | lb-v2-policy |
| `org check-hooks` | `config.validate` | lb-v2-policy |
| `org hook` | `policy.evaluate` | lb-v2-policy |
| `org hook-history` | `records.query` | lb-v2-integrate |
| `org init` | `org.bootstrap` | lb-v2-templates |
| `org instance add` | `org.change.propose` | lb-v2-approval |
| `org refusals` | `records.query` | lb-v2-integrate |
| `org render` | `org.change.propose` | lb-v2-approval |
| `org roles init` | `org.change.propose` | lb-v2-approval |
| `org roles list` | `config.read` | lb-v2-policy |
| `org validate` | `org.validate` | lb-v2-templates |
| `plugin` | `config.read` | lb-v2-policy |
| `policy evaluate` | `policy.evaluate` | lb-v2-policy |
| `policy get` | `policy.get` | lb-v2-policy |
| `records append` | `records.append` | lb-v2-integrate |
| `records export` | `records.export` | lb-v2-integrate |
| `records get` | `records.get` | lb-v2-integrate |
| `records import` | `records.import` | lb-v2-integrate |
| `records query` | `records.query` | lb-v2-integrate |
| `refusal` | `records.query` | lb-v2-integrate |
| `report` | `report.submit` | lb-v2-messaging |
| `report submit` | `report.submit` | lb-v2-messaging |
| `report watch` | `mail.list` | lb-v2-messaging |
| `secret import` | `secret.import` | lb-v2-secrets |
| `secret key` | `secret.key` | lb-v2-secrets |
| `secret list` | `secret.list` | lb-v2-secrets |
| `secret revoke` | `secret.revoke` | lb-v2-secrets |
| `secret rotate` | `secret.rotate` | lb-v2-secrets |
| `secret stage` | `secret.stage` | lb-v2-secrets |
| `serve` | `serve` | lb-v2-integrate |
| `service status` | `health` | lb-v2-service |
| `settings` | `config.read` | lb-v2-policy |
| `start` | `brief.start` | lb-v2-templates |
| `state events` | `event.tail` | lb-v2-lifecycle |
| `state lanes` | `lane.list` | lb-v2-lifecycle |
| `state rebuild` | `store.rebuild` | lb-v2-service |
| `state verify` | `store.verify` | lb-v2-service |
| `store rebuild` | `store.rebuild` | lb-v2-service |
| `store record` | `records.append` | lb-v2-integrate |
| `store search` | `records.query` | lb-v2-integrate |
| `store verify` | `store.verify` | lb-v2-service |
| `ticket issue` | `ticket.issue` | lb-v2-identity |
| `tool` | `records.query` | lb-v2-integrate |
| `upgrade apply` | `upgrade.apply` | lb-v2-packaging |
| `upgrade plan` | `upgrade.plan` | lb-v2-packaging |
| `whoami` | `identity.self` | lb-v2-identity |

The required checks for this contract lane are gofmt and go vet for Linux and
Darwin, with Linux checked both normally and with `laneboss_faults`. They prove
static consistency only. Implementation acceptance, kernel canaries, actual
vendor authentication/continuation, human verification, installer walkthroughs,
judge calibration, hook deletion and the two concurrent ladders remain assigned
work in v2-lanes.md. No stub result or compile is a runtime pass.

## 13. Integration amendment ledger (draft.2)

These amendments add no generic RPC and no third driver. Schema 2 draft
artifacts must be installed as matched bytes; an older strict decoder cannot
consume a new optional field and is not a supported mixed deployment. Existing
API method signatures remain unchanged. The wire appendix above includes every
new optional Record/RecordQuery field.

| Amendment | Why / consumers that must rebase |
| --- | --- |
| R108 default constants and `ResolveJudgeConfig` | `judge`, `policy`, `guidance`, `templates`, `assembly`, docs and E2E must resolve an unspecified provider/model to self-hosted Clef-flash, preserve deployment/tokenizer/context pins and refuse unknown/hosted providers. No provider substitution on outage, Jev comparison or shadow-promotion gate. |
| Canonical decision ingress | `identity`, `service/store`, `records`, `approval`, `guidance`, `dashboard` and `migration` must enforce isolation.md §4/§8. `decisions.mutate` is human-proof; L6 uses D6. Observations/proposals never become cross-lane authoritative guidance. Fresh ledger/coverage/archive outcomes come from their trusted worker, not a caller's collection label. |
| Exact record lookup and revision metadata | `Store.Records` applies optional `record_id` before returning any bytes/count/cursor, with the same ACL as other reads. Empty collection is valid only with an exact ID. ID lookup uses keyword mode, empty query/cursor and limit 1; hidden/absent gives an empty page. `records.get` then returns not_found. `store`, `records`, `guidance`, `dashboard`, `migration` and record workers preserve related IDs, action and separate annotation/feedback references. |
| Durable typed record receipt | Draft.3 generalizes this draft.2 amendment to Transaction.Reply and Commit.Reply for every mutating method. The record-only fields are removed, and records consumes the generalized exact reply. §14 defines reservation, replay and atomic consumption. |
| Runtime dependency closure | `service.Server` implements `api.ServiceHost`: BindRuntime(ctx, RuntimeServices), ServeInstalled(ctx), Close(). `lifecycle.Service` implements `api.WatchdogBinder`. `service`, `lifecycle`, `watchdog` and `assembly` must rebase together for hosted acceptance. Missing interfaces remain typed not_implemented, not disconnected background services. |
| Initial streaming response | `client.Stream` retains its existing signature but returns an `api.ResponseStream`, exposing Initial() Response before Next(). The common CLI validates/prints that initial snapshot, then consumes correlated increasing frames through a real end. EOF is failure. Selected-life/run/service-origin filtering also applies before until, including snapshot events. `client/service`, lifecycle and common CLI must rebase for stream acceptance. A stream lacking Initial remains typed not_implemented. |
| Confined record/resource ports | `api.RecordWorker` owns Import/Export/Search, `api.ResourceWorker` owns Launch/Run/Harvest/End/List. Both take authenticated Scope and typed input. Integration owns their implementations; grants/dataworker supplies confinement and service/store supplies durable effects/receipts. Nil ports fail explicitly. They are not implemented by calling legacy entry points under the service UID. |
| Common exact CLI form | `cli.Invocation.Invoke/InvokeRaw` implement the shared request path. Feature command owners can use Invoke for ergonomic flags and need not duplicate the file form. `--binding FILE` is absolute; `--proof FILE` is an envelope proof reference; request/idempotency IDs can be retained with the corresponding named flags. Unknown/duplicate common flags refuse. Every state call still passes one explicit matching configuration. |

`api.DecodeObject` is the shared bounded structural decoder: exact tags and
required fields, no duplicate keys, case aliases, explicit nulls, trailing JSON,
invalid UTF-8/unpaired surrogates or noncanonical base64. Module validators still
check enums, IDs, generation, provenance and authority. `api.CanonicalJSON` and
`RequestDigest` implement the frozen JCS intent digest, excluding proof and
transport IDs. Transport owners retain original frames/source bytes separately.
These helpers do not authenticate an endpoint or authorize a mutation.
Structural refusals identify a closed frame kind, compiled object/field path
and reason. Unknown input member names and array indexes use fixed wildcards;
diagnostics never quote values. Raw refusals separately name empty input, frame
limit, UTF-8, surrogate, duplicate, depth, syntax, trailing or nonfinite failure.

Serve boot data is a protected file, not a lane API. The exact
`assembly.Installation` object has schema `laneboss.service-install.v2` and
fields `schema,config,service_uid,artifact_sha256,binding_file,state_directory,
socket,secret_directory,secret_key_handle,runtime_manifest,judge,judge_endpoint`
plus optional `judge_credential_handle,judge_alternative,launch_enrollment,admin_enrollment`. Judge is JudgeConfig and runtime_manifest
is a committed manifest BlobRef; the credential/key fields are handles only.
The admin/packaging lanes supply this file and their installed client binding.
`judge_alternative`, when present, is exactly `{config: JudgeConfig, endpoint:
string, credential_handle?: ID}` and enrolls the other supported provider.
These boot entries describe installed capabilities, including verified deployment
pins, endpoints and credential handles; they never select the active judge.
`EffectivePolicy.Judge` at the authenticated policy generation selects provider,
full model name and pins. Both Clef and TypeSafe ports are wired lazily; no
provider is constructed or contacted if the approved deployment has no matching
enrollment (`prerequisite_missing`). A D6 provider switch can use the other
enrolled endpoint without restarting or silently following boot-file order.
No default user HOME/state path, environment credential discovery or automatic
administrator setup is permitted. Start with:

```console
laneboss serve --config NAME --installation FILE
```

The boot file/binding/artifact and their parents are root-owned without shared
writes or symlink redirection. State, secrets and runtime directories have
exclusive dedicated-service-UID ownership and cannot overlap. The running UID
must be that nonroot service UID, and the actual artifact digest must match.
Serve's optional --binding can only repeat the installed binding, not replace it.
`ServiceHost.BindRuntime` compares RuntimeServices' config/socket/artifact with
its verified installed binding, and must bind durable effects, watchdog and
recovery dependencies before readiness. `ServeInstalled` creates only its
separately ACL-protected lane/human endpoints; it does not expose a shared
management endpoint to lanes or unlink a live/stale socket as recovery. Close
drains/cancels owned work and closes the store; shutdown failure is not success.
These listener/host operations still need the service lane's implementation.

Assembly constructs only Claudock and Codex agent adapters. It registers every
catalog method exactly once under its owning module and separately requires
event.tail/lane.attach stream handlers. A missing constructor/handler or
required startup binder stops startup with its typed owner error. Credential
projection binding is deferred to projection-bearing Prepare as specified
below, so its shipped stub does not block health or enrollment. Registration completeness proves
wiring only; it cannot detect a handler that lies about behavior. The installed
black-box cases and independent review remain the release gate.

Record text is a committed `record|report` blob, nonempty and at most one decoded
chunk (256 KiB), valid UTF-8 without binary controls or detected credential
shapes. Ref/hash/size are checked against actual scoped store bytes before any
append. Generic lane appends are observations/reports only. Private imports may
target those same collections; canonical/history imports need verified human
proof and a confined parser preserving provenance. Import cannot promote
historical lifecycle/approval/ledger claims into current authority. Exports,
vector/hybrid retrieval and cloud operations remain unavailable until their
confined implementation and evidence are supplied. `decisions stats` also
returns typed not_implemented until an aggregate port replaces the frozen
placeholder alias; returning a query page would not implement statistics.

## 14. Consolidated draft.3 amendment with draft.4 corrections

This is the single amendment for the ten supplied lane requests, R108 and
draft.2 §13. The Go definitions in api's new bindings, transactions, humanstate,
objects, sources, turns, delivery, deployment and projections files are the
normative internal signatures. Current consumers are updated together against
typed failing stubs. A stub's interface assertion is not implementation evidence.
Independent supervising review remains required before landing the revision.

EffectRecord.State has one closed vocabulary: pending, claimed, completed and
failed (EffectPending, EffectClaimed, EffectCompleted and EffectFailed). A held
EffectLease always has state claimed, with its existing exact ClaimID, owner,
generation and expiry checks. Credential projection, materialization, deferred
completion and worker identity use the same EffectLeaseClaimed predicate.
The store validates ValidEffectState on every persisted record. CompleteEffect
seals completed on success or failed on failure. This vocabulary is distinct
from Operation.Status, where pending and running remain valid operation states,
and from the separate continuation-intent status. Running is not an effect
state or an alias for a held claim. TestSharedLease applies one lease-state
value to all three real validators with their distinct closed effect payloads;
no helper effect is forged into a worker or publication effect.

The public protocol/schema remain laneboss.rpc.v2 / 2 for this unreleased draft.
Bindings additionally require exact `contract_revision: v2.0-draft.4` and matched
artifact/version. Earlier draft processes cannot mix with draft.4. Required new
JSON fields below are breaking draft changes, not silent optional additions.
No public RPC is added, no generic command/root-path API is introduced, and
Driver remains only claudock-cli or codex. Internal catalogs are protocol/effect
discriminants, never a command/tool allowlist.

### Binding, connection lifetime and every-message identity

InstalledBinding has schema `laneboss.binding.v2`. Its complete tagged field
map is in the appendix: configuration, contract/protocol/schema/version,
installation/endpoint generations, class, artifact digest, host service UID/GID,
mapped service UID/GID, socket, selected backend and optional launch/target/job
references. Class is lane, human or worker; the helper continues to use the
separate root-owned laneboss.admin.v2 binding and private helper endpoint.
Host service UID/GID are nonzero; mapped IDs may be zero inside a namespace.
Only the lane/worker class carries a launch and exact life/run. Worker also
requires its job lease. A human binding carries none of those lane labels.

Protected discovery is `/etc/laneboss-v2/bindings/CONFIG.json` outside a lane.
Inside a lane, use its installed read-only `/run/laneboss/binding.json` projection
or an explicit absolute --binding/--binding-file naming that same authorized
projection. The two flags are aliases; passing both is a duplicate, not a binding
switch. No HOME search, environment credential discovery or outage fallback.
Root owns installed boot/human bindings; the service may generate read-only
per-run child bindings under its protected runtime tree. Clients verify file
and ancestor ownership/modes/identity and the actual mapped server credentials.
Bindings alone confer no human authority and their IDs are not bearer tokens.

Scope.Connection, Scope.Frame and Scope.ReadView are internal/nonserializing.
ConnectionContext owns a unique connection ID, InstalledBinding, lifetime-pinned
VerifiedPeer and current read authority. Transport owns Close, including watcher
disconnect; identity borrows the handle and never substitutes a launch-ID map
or reuses equal serialized Scopes as process identity. FrameContext retains the
exact bounded request bytes and verifies each fragment against that connection.

Authentication has one required order. Service transport accepts the raw native
socket and creates ConnectionContext with its unique ID, `Conn()` and the
listener's verified InstalledBinding, initially without peer/read authority.
`Authenticator.Authenticate(ctx, connection)` calls
`PeerVerifier.Verify(ctx, connection.Conn(), connection.Binding())`. The peer
verifier reads kernel facts and, for lane/worker endpoints, resolves containment
through the helper registry using that binding; it needs no Scope or identity
callback. Human endpoints verify their connector lifetime against the enrolled
human endpoint, without looking for a lane cgroup. Identity calls `BindPeer`
once, resolves launch/enrollment/current policy from the store, and returns a
Scope containing that same connection. Only then may transport dispatch frames.
Any failure closes the peer/connection. Public health is the single exception
(draft.4 fixes 8 and 10): before Authenticate, transport reads exactly one first
frame with a fixed two-second read deadline measured from accept, and enforces
MaxFrameBytes before authentication. Linux pins every fragment's SCM_CREDENTIALS
to the socket peer. Darwin requires the native per-frame audit token and the
writer's pinned kernel lifetime; connector-only evidence is insufficient, and
an unsupported native path stays closed. Invalid JSON, oversize frames, unknown
fields, and health with proof, objects or fields beyond HealthRequest close
without any reply. A valid `health` receives Health with no Scope and no store
read beyond the health snapshot, then the connection closes without reading a
second frame. The health reply is the only bytes written before Authenticate.
Every other well-formed first method runs Authenticate before dispatch; failure
closes without reply or dispatch. The per-peer admission limit applies to public
health, keyed by the kernel UID. No component waits for an authenticated
Scope to obtain the kernel facts needed to create it. Binding is supplied per
connection, so identity does not cache one lane/human binding at construction.
`BindReadAuthority` is used only by identity after the human.session proof and
session commit on that connection. Rebinding a peer, transferring a read session
to another connection, or binding after Close refuses.

On Linux set SO_PASSCRED before accepting/using the socket and read every frame
byte through recvmsg/ReadMsgUnix. Require exactly the expected SCM_CREDENTIALS
writer on every fragment; bind it to the connector UID/PID/generation and live
containment. Reject mixed writers, missing/extra/truncated control data and all
SCM_RIGHTS, closing any received descriptors; an unauthenticated connection
closes without a typed reply.
SO_PEERCRED/SO_PEERPIDFD alone describe the connector, not every later writer.
Darwin must provide equivalent native evidence or keep the operation unavailable;
an audit-token connector alone cannot establish a passed-descriptor defense.
Recheck current lifetime/endpoint/launch/grants on every operation and delivery.

ContainmentRegistry is a trusted helper/peer dependency. Register only a
helper-created binding with its config, UID lease, life/run, backend, boot and
allocation generation. Linux registration pins an owned duplicate of the real
cgroup directory; native Darwin resolves the current protected UID lease and
kernel lifetime. It is not a client path/label or a generic descriptor-transfer
RPC. Peers receive the registry at New, resolve actual kernel facts against the
installed endpoint, and reject missing, revoked, replaced or prior-boot leases.
Never compare every descendant's start generation to the leader's generation:
the descendant has its own pinned lifetime within the registered containment.

### Helper, committed launch and runtime resolution

HelperControl extends Allocate/Prepare/Release with RegisterSpec, OpenGate,
ObserveGate, StopGate, AbortGate and ReconcileGate, plus the trusted containment
and runtime resolvers. This fixed service-to-helper surface supplies no root
shell/argv, arbitrary host path, URL or executable selector. All calls use the
installed authenticated helper channel and retain causal operation/effect IDs.

Allocate / RegisterSpec / Prepare / OpenGate / StopGate / AbortGate / Release carry the
required Cause intent, using their distinct helper kinds. Helper IPC objects
use the exact snake_case tags below; abort also binds its effect ID.
Release takes HelperReleaseRequest with cause, lease and the service's
ProcessObservation as a comparison claim only. Only the service invokes it over
the authenticated helper channel. Under its lease lock the root helper
independently re-observes its registered containment: Linux requires no tasks in
the pinned registered cgroup; Darwin requires the protected UID lease/kernel
process set to be quiescent. It also measures no live connections, queued jobs
or writable exports for that lease. Unknown, nonzero, or disagreement with the
caller's process facts returns `containment_unknown` and retains the lease.
StopGate performs any required cgroup kill/UID stop before release; Release
cannot perform an abort/stop or infer zero from a failed census. Allocation
cannot reuse the UID while these measurements and release journaling complete.

For normal completion, the helper shall validate its original wait owner,
the exact process handle and zero survivors, then durably commit the native
exit before removing the live containment registration or its cgroup.
The retained terminal record shall survive removal and helper restart.
If that commit fails, cleanup shall retain ownership and refuse completion.
Credential return shall import any supported refresh through the existing
broker checks before freeing the canonical seat.

Revocation, cancellation, boot mismatch and lost native ownership shall
remain distinct from normal completion. They may deny live authentication
before a terminal record exists and shall retain the applicable rotation
requirement. A generic `containment_unknown` response shall never prove a
natural exit or authorize credential release.

Release returns ReleaseReceipt containing the helper's own process and resource
counts, containment/backend, lease/operation/effect IDs and measurement time.
CompleteEffect verifies those bindings, applies ValidateReleaseReceipt and
commits EffectOutcome.Release and `helper.released` as that measured receipt;
caller-supplied Survivors/EffectOutcome.Observation cannot substitute for it.
Effects have distinct helper allocation/preparation/release/abort payloads and
typed lease/prepared/process outcomes, so service completion can correlate them
without interpreting a worker argv or relying on the root lease journal alone.

RegisterSpec takes PreparedSpecHandoff: the complete service-built LaunchSpec,
original committed bytes, JCS spec digest and config/request/operation binding.
Its Cause is helper_register and retains the parent operation/effect. The helper
independently verifies its lease/target/budget/grants/runtime pins,
registers immutable bytes and returns PreparedSpecReceipt. Helper.Prepare resolves
only that registered ID/digest. It prepares a nonexecuting gate. RuntimeManifest
uses `laneboss.runtime.v2` with generation, artifact/bootstrap pins, enrolled
root-relative RuntimeObjects and endpoint projections. RuntimeResolver performs
post-spec verification; LaunchSourceResolver.ResolveLaunchSources selects the
pre-spec inputs below. Both resolve only protected objects; neither a blob ID
nor logical cwd is
treated as a host path. NetworkLease binds actual namespace/forwarding/packet
ownership to the grant set and enrolled endpoint IDs; no host-network default.

The service atomically persists LaunchBindingRequest's LaunchRecord and
PreparedLaunch with identity.bound. The store stamps IdentityCommit's actual
event ID, committed sequence and record digest. BindLaunch accepts that tuple,
looks it up through StateStore.LaunchBinding, and checks exact life/run, prepared
ID, gate, spec, containment, grants and endpoint/policy generations. It returns
the permit only from that committed receipt. Record.ID is never PreparedID.
OpenGate consumes the matching permit once; identical retries reconcile to the
same process, while changed IDs/digests refuse. After restart use ReconcileGate
and real containment observation before doing anything else. Unknown state never
opens another gate or releases/recycles its lease.

AbortGate has a distinct nonexecuting AbortReceipt. It independently proves the
gate never opened and actual UID/cgroup quiescence; it may record prepared state
with no invented exit code/process. Release cannot stand in for abort or gate
opening. Helper journals support reconciliation but do not replace causal
service events. CompleteEffect commits helper allocation/release receipts
and their original requester exactly once before downstream effects proceed.

Backend selection is protected binding data, not a new StartRequest/CLI flag.
Admin binds the selected launcher probe. Doctor projects its actual result as
isolation.BACKEND, including isolation.darwin-seatbelt unavailable on Linux.
An OS-mismatched backend can be represented diagnostically but every launch/
control operation returns unsupported with its backend owner, CLI exit 69,
without executing an agent. Native packet/listener feasibility still requires
the designated-Mac cells; compilation does not establish it.

### Durable requests, guards, objects and read snapshots

StateStore composes the existing Store and the typed ReceiptStore, EffectStore,
IdentityStore, ObjectStore, OrgStore, TurnStore, DeliveryStore, DeploymentStore,
LaunchStore, CaptureStore, ChannelJobStore, LaunchDataStageStore and PolicyStore
ports. It remains the sole service-owned writer. No component opens its own
parallel projection database. Every current consumer dependency names StateStore.

For a public mutation the dispatcher authenticates the current connection/frame
and object authority, prepares the exact Request, then LookupReceipt **before
calling module preflight**, proof consumption or base comparisons. Its key is
the authenticated config/principal/life plus method/idempotency key, not an
operation ID. Same digest returns the stored receipt; changed digest conflicts.
ReserveRequest persists a pending operation and exact frame before external
work; it authorizes no effect on its own. A pending retry awaits that operation
through AwaitReceipt, never executes it twice. Current revocation/visibility
checks precede replay. A new request ID changes response correlation only;
the original result/events/requester remain the original receipt.
PrepareRequest refuses an empty mutation IdempotencyKey, naming
`--idempotency-key ID`; callers retain it for the same change across invocations.
Only read keys and request correlation IDs may be generated afresh. The CLI's
inline record upload derives each begin/chunk/commit key from that retained
parent key and submethod; changed bytes with the same key conflict. Human record
and decision writes use `--content-ref FILE` (committed BlobRef JSON) or the exact
`--request FILE` form: upload first, confirm the known reference, then invoke the
mutation with its proof and retained key. `--file` and `--content-ref` are
exclusive. `--file` plus a pre-existing operation proof refuses before upload.

Every common `--request FILE` route shape-decodes its retained bytes, then runs
the owning feature's local semantic input validator before reading/preparing a
proof, generating request metadata or opening any connection. It returns that
validator's exact error, including invalid_request, message and module Owner;
an arbitrary binding/transport/key failure is not semantic validation. Alias
checks, retained keys, shared human.session lifetime and service authorization
still apply. No feature is special-cased in this common ordering.

Feature command adapters register their existing validator at initialization
with `cli.RegisterInputValidator(method api.Method, owner string,
validate func(json.RawMessage) error) error`. The method must exist and owner
must equal MethodSpec.Owner; nil, duplicate or foreign registrations refuse.
The hook receives a private copy of the retained bytes and cannot replace the
body sent to the socket. A missing file-form validator returns the owning
module's typed not_implemented before transport; it never silently skips the
check. Typed ergonomic Invoke continues to require its owning adapter's own
semantic preflight, and invokes the registered check too when present.

Guidance registers its existing lbV2GuidanceFileRequest through a wrapper that
returns that function's error. Approval registers ValidatePropose/Get/Approve/
Apply after exact decoding, and every other feature does the same for its own
methods. All eleven integrate-owned methods register production Records input
validators, including append, decisions, import and every box method. The
service also calls those validators and keeps its original in-place collection,
content, action and generation checks. CLI checks are additional early refusals;
socket/dashboard callers still face service validation and atomic store CAS.
The explicit integrateNoFileInput inventory marks each other common file form
unavailable until its owning adapter registers; successful registration removes
that declaration. TestFileInputCatalog audits every MethodSpec, refuses gaps or
overlapping declarations at any owner, and permits no unavailable exception for
integrate's own methods. The feature stubs in the isolated
integration tree have no invented semantic success: their adapters must register
as the real feature sources are combined. The common-hook fixture is not proof
that an unregistered adapter is complete. Guidance's original
TestCLIRejectsMalformedFile and another feature's own semantic negatives must
run on the exact combined tree after registration, in both build modes.

Transaction.Reply/Commit.Reply replace draft.2's removed RecordResult fields.
RPCReply is exactly one final typed Result (selected by MethodSpec) or Error. Transact
validates the reply against the corresponding events/projection, stamps actual
commit time/operation IDs/sequences (including Mail.queued_seq in payload,
projection, effect and reply), then retains the exact final reply bytes together
with CAS, guards, writes and effects. Replay returns those bytes, not a later
projection. A failed module preflight after reservation is completed by an empty
state/effect transaction carrying its typed Error; failed authorization/shape
before reservation is not an accepted operation. Returning pending is only valid
for the RPC's documented Operation shape. Synchronous Record/Mail/ChangeReceipt
methods await their real durable result or return a typed deadline/unavailable
error with the operation reference.

For synchronous guarded effects, the one pending representation is
Transaction.Deferred: *DeferredReply, mutually exclusive with Transaction.Reply.
DeferredReply contains Key: RequestKey, OperationID: ID and EffectID: ID. It
is internal data, never an RPC Result, Error or Operation substituted for a
ChangeReceipt. The public write catalog currently permits it only for
org.change.apply with exactly one ApplyChange effect and org_publish context.
Other public mutations still require their final Reply. An internal transaction
cannot carry Deferred or a public Reply. A public apply cannot submit a final
success transaction; its success is sealed only through the publication effect.

The pending apply transaction retains the authenticated request identity,
original RawRequest frame bytes, reservation key/operation and causal request/effect IDs.
Scope.Request may carry a canonical re-marshalling of Params: protocol, schema,
config, method, request ID, idempotency key and digest must match the decoded
original frame exactly, both envelope proofs must be nil for this L6 apply,
and Params must match through CanonicalJSON with the verified RequestDigest.
Whitespace or key order alone is not a different intent. Changed params or
metadata refuse. RawRequest itself remains the exact original verified frame;
canonical comparison never replaces or reserializes its retained bytes.
It requires the current L6, the actual org/base CAS and an ApprovalUse matching
the apply's change, approval, manifest and base. Transact atomically checks and
consumes/reserves that approval for this operation once, persists the guarded
effect, org publication gate and Deferred on the same reservation, and returns
Commit.Deferred with nil Reply and pending/running Operation. The store checks
the org ID against the retained change, not just the submitted comparison's
generation. It verifies the original transport frame before commit, copies the
verified bytes, and compares them with RequestReservation.RawRequest under the
store boundary. Deferred alone never authorizes an effect or creates another
reservation. Re-submitting that committed transaction replays its original
pending commit without consuming ApprovalUse or inserting the effect again.
Once Deferred is committed, a later public Transact cannot seal any Reply,
including an empty-state Error; only the claimed CompleteEffect path can do so.
The ordinary preflight-error transaction is available only before a guarded
effect has committed on that reservation.

MutationReceipt.Deferred persists the operation/effect/key binding while Reply
is nil. An authorized same-key/same-digest retry calls AwaitReceipt for that
reservation; it cannot rerun apply preflight or take a second approval. A retry
request ID only correlates that retry's eventual frame; it never overwrites the
original RawRequest, requester or causal request ID. A different digest conflicts.
Current visibility/revocation checks still precede await/replay. Await releases
the global write lock; it waits for the durable reply rather than treating an
outbox commit as success. A disconnected/expired frame does not cancel or clone
the persisted effect. A transport deadline/unavailable error names the original
operation and is not persisted as its final publication result; that frame gets
no later second response. A retry may await the eventual result on its own frame.

The publisher claims that exact persisted effect through ClaimEffect. A running
claim has a nonzero generation, claimant, claim ID and expiry. Recovery reclaims
the same effect with generation CAS, never a new apply operation. It performs
the existing immutable generation publication, durable marker, approved-pointer
swap and reconciliation protocol outside the store write lock. The per-org
dispatch/read gate remains until DB and filesystem completion agree. Uncertain
publication remains pending for reconciliation; it cannot be recorded as a
definite failure simply because a wait or connection ended.

EffectOutcome.Reply is *DeferredCompletion, containing Deferred: DeferredReply
and Reply: RPCReply. CompleteEffect is the sole completion port. It checks
ValidateDeferredCompletion against the store's pending MutationReceipt and its
current EffectLease, then atomically commits the measured outcome, org_publish
projections/events, publication gate transition and exact final reply on that
original reservation. A succeeded outcome has a real Publication: ChangeReceipt
identical to the typed reply, with the original change/approval/base, actual next
generation, manifest and publication time. The store authenticates those facts
against the approved change and filesystem marker; matching shapes alone are
not publication evidence. A failed outcome has Error identical to Reply.Error,
the original operation ID, and no Publication or success result. It records the
failure of the already guarded effect; it is not a public error transaction
carrying fresh effects. Neither completion path consumes any approval/proof
again. It cannot queue a replacement ApplyChange under the error reply.
Completion-derived projections/events still pass the org_publish internal
catalog. Their internal Transaction carries no public Reply/Deferred; the final
reply is attached from EffectOutcome.Reply inside the same CompleteEffect commit.

The completion carries no new public Transaction or reservation. The store must
refuse a foreign/stale claim, generation, frame/key/operation/effect, missing
effect, competing reply or attempt to replace a final reply. The validator
returns invalid_request owned by lb-v2-service on invalid deferred completion.
An exact duplicate of an already committed completion may only replay the
retained receipt with Replayed true and no new event/write/reply; a differing
completion conflicts. MutationReceipt may retain Deferred as immutable
provenance after Reply is final. The store tests final Reply first before any
pending validation. Every waiting authorized frame receives one final typed
ChangeReceipt or Error, and CLI writes only that final response. No public RPC
or response schema changes. Approval, service/store/outbox/publisher and their
fixtures must consume this representation together before claiming D6 green.

Compare.Kind is the closed catalog lane, grants, org, change, approval, record,
mail, guidance, continuation, endpoint, upgrade. ID selects that projection and
Generation 0 means **must be absent**; positive values require exact current
generation. Unknown kinds and ignored comparisons fail. Shape validation is not
authorization. Store rechecks live identity, expiry, revocation and current
delegation under the commit boundary, with replay first. It never holds the
global write transaction across a judge, worker, capture or filesystem wait.

Each TransactionGuard has exactly one proof, ticket, approval or cancellation
check. IdentityStore.AuthorizationTarget resolves the operation's real target
and base from the typed request/current state, without widening public ACLs.
Existing life/grant/change/record/plan mutations target that authentic ID;
creates use the configuration-local enrolled collection or requested new lane/
org name and absent base. The intent digest always covers the entire exact
operation. Explicit expected generations come from that request; operations
without one bind the actual current generation into the challenge.

HumanVerifier.Challenge/Confirm now take Scope, including installed endpoint,
principal and connection. Enrollment provides the pinned origin/RP and real
credential IDs/keys/revocation/counter, not a credential label from the caller.
CheckProof returns immutable VerifiedHumanProof facts and does **not** consume.
ConsumeProof is removed. Confirm atomically compares/uses the stored challenge,
updates the verified signature counter and records proof/assertion evidence.
The chosen handoff adds Objects only to the human.confirm row alongside
its Challenges, Counters and Proofs. This preserves the existing identity
producer's single atomic transaction, as required here and by isolation.md
§4 [human identity and operation-bound confirmation](isolation.md) (section "Human identity, tickets and direct approval").
An unrelated upload or separate object_retain transaction is not an atomic
verified-assertion handoff. No other human method gains object-write authority.

A successful confirmation carries exactly one consumed StoredChallenge, one
CredentialCounterChange, one VerifiedHumanProof and one ObjectWrite. The object
is precisely that proof's AssertionEvidence: same ID, artifact class, byte
length and SHA256, Origin identity, no InputRefs, a new generation-1 object.
Its bytes are encoding/json's encoding of the exact typed HumanConfirmRequest
that identity verified, preserving the client-data, authenticator-data and
signature byte arrays. The hash is recomputed from those retained bytes; even
a self-consistent blob/ref pair for a different assertion refuses. The reply
and human.confirmed event carry that proof's exact Ref, never the assertion.

The evidence ACL must be private to the resolved human Scope.Actor and Config,
with no LifeID or Participants and no broader audience. Proof principal/config,
credential, endpoint generation, challenge/target/digest/expiry and the counter
handoff must agree. ValidateTransactionShape enforces these structural bindings.
Store commit additionally authenticates the bound identity producer and original
verified frame, compares the currently enrolled credential/key/generation and
unused challenge/current counter, and checks the actual verified assertion
facts, object bytes/hash/ref and ACL under the same atomic boundary. It checks
that the evidence object/proof IDs are absent and commits evidence, challenge
use, counter, proof, event and exact reply together or none. A proposed
VerifiedHumanProof or a well-shaped object alone is not verification authority.
The store must not widen the evidence ACL during reads, replay or rebuild;
another principal/configuration/lane cannot read it. Verification failure or
changed enrollment/challenge/counter commits neither evidence nor proof. The
normal empty-state preflight Error transaction still carries no Objects.

The mutation then uses ProofUse under Transact's commit lock: same principal,
config, method, target, digest, base, expiry and unconsumed nonce. Proof use,
approval/result persistence and the idempotency receipt are one commit; emit
human.proof.used with actual credential/nonce/operation facts. Root start/adopt
similarly consumes TicketUse at its issued level/role/grants/config/expiry.
`root_ticket_id` is evaluated only on an installed human-class connection.
Lane/worker connections carrying one are forbidden before any ticket lookup.
TicketUse also binds issuing PrincipalID, Config and EndpointGeneration, checked
against the original ticket.issued provenance; possession of a ticket ID never
selects a privileged root path on a lane connection.
The existing same-principal rule is intentional: the issuer redeems its own root
ticket under that same configuration and human endpoint generation. Another
enrolled principal or an endpoint rotation requires a newly issued ticket and
fresh issuance proof. A new connection within that generation is allowed; a
ticket is not tied to its issuing socket. This keeps the conservative draft
interpretation of isolation.md §4's [human-issued, non-transfer-to-lane tickets](isolation.md)
and [operation-bound human approval](isolation.md) (section "Human identity, tickets and direct approval")
(source paragraphs at lines 1028–1031 and 1107–1115). It does not add transferable
bearer authority. Identity/lifecycle/store all apply this one interpretation.
Retries replay before consuming either item. Initial admin_enroll is an absent
enrollment baseline under the fixed administrator ceremony; later enrollment
changes require existing human approval/D6, not a self-enrollment RPC.

Challenge/proof connection IDs are audit correlation, not bearer authority.
Confirmation and exact operation proof use may cross human connections only
with the same resolved principal, class/config/current endpoint generation,
valid assertion/target/digest/expiry and atomic one-use check. A lane connection
never receives that exception. A read session instead belongs to the exact live
human connection (or the dashboard's server-owned cookie context), closes with
it, and expires after five idle minutes / thirty absolute minutes. Public
HumanSession.ID is no transport credential. Interactive CLI/UI flows keep the
client open across confirmation/session/read; separate CLI invocations do not
gain read authority by carrying that ID or claiming the login UID.
For any non-mutation CLI read, or a session-scoped staging/preview mutation,
`--proof FILE` is a proof for `human.session` with
params `{}`. InvokeRaw first invokes that mutation, using a retained key derived
from config/proof ID, then invokes the requested read on the same socket. It
does not attach that proof to the read as an ambient token. Multiple calls and
upload subcalls in one Invocation share its socket until the command exits;
an already-open Invocation.Client is borrowed, not reopened/closed by InvokeRaw.
A new CLI invocation needs a fresh session proof. Replaying an old session
receipt cannot attach its read authority to a new connection.
HumanSessionMethod marks blob.begin/chunk/commit, secret.stage, policy.evaluate,
guidance.select and judge.ask. The latter three are bounded previews/audits
under the current scoped policy/grants; they cannot select new policy/provider
authority or approve a decision. Other human authority-bearing mutations still
need their exact operation proof or root ticket. An already-open client may
stage multiple chunks on one session. Across CLI invocations a fresh verified
session is required, while the upload/object ACL stays bound to the same
principal/configuration. Upload IDs and session IDs are never bearer authority.

The same transaction's StateWrites is the closed set of typed enrollment,
identity, upload/object, policy/org, decision/turn/guidance/continuation, mail and
deployment projections. It is not a general map/SQL API. The store validates
which public method or trusted InternalKind may emit each write/event. Internal
jobs carry InternalIntent with actual service/scheduler/watchdog/worker actor,
causal requester/request/operation, effect, life/turn and cancellation epoch.
They have no invented public watchdog method and cannot borrow a mail sender.

The following public-method matrix is normative and mirrored by
`api/write_catalog.go`. A row permits only its named StateWrites fields,
submitted event kinds and Effect payloads; all other fields/events/effects
refuse. Every non-mutation method in Methods permits no writes, events, effects
or guards. Public mutations require exactly one Transaction.Reply or the
catalog-permitted Transaction.Deferred described above. A final error reply has
no state/effects/guards/events. Record projections are derived directly from
`record.appended` / `decision.changed` events; there is no separate Records
write field. Store-owned operation receipts/events and `human.proof.used` /
`ticket.redeemed` are synthesized from checked guards under the commit lock,
never caller-provided authority. Retained outputs of read methods use the
separate trusted object_retain port, not a mutating read transaction.

Every row additionally requires the current catalog access class, object ACL,
matching config/digest/reservation, comparisons and actual bound module. `P`
means ProofUse, `T` TicketUse, `A` ApprovalUse, and `C` CancellationCheck.
All human authority-bearing mutations use P except root lane.start/adopt (T).
Human challenge/confirm have their enrollment/assertion ceremony. Bounded blob
and encrypted-secret staging and the three preview methods above use `S`, the
current verified human connection read authority. Lane/worker callers never gain human authority from
a field. C is required when an effect/continuation depends on a life epoch.
An empty cell is `none`, not an unrestricted extension point.

For an S method, the dispatcher obtains a fresh Scope with WithReadAuthority
before reservation/preflight and outside the store write lock. Scope.ReadAuthority
is internal/nonserializing and includes ReadAuthority.ConnectionID. Shape
validation requires a human-class installed binding and exact principal/config/
connection / endpoint-generation / session / credential facts; nil or borrowed facts
refuse. The connection's ReadAuthority port checks expiry/revocation/lifetime.
Store authorization rechecks those facts against the current stored read session
and transport state before replay and commit, with its current clock. It must
not call back into transport/store readers while holding the write lock. A
cached scope alone does not establish current authority. S authorizes only
private inert uploads/previews; owner ACLs, class/provenance, upload limits/hash/
contiguous-byte rules and approved judge budgets remain mandatory. Lane/worker
upload authority still comes from their normal authenticated scope/grants;
they cannot borrow S. No proof/ticket/approval guard is synthesized by staging.
Successful human-read transactions always require bound human read authority,
even when the proposed Scope says lane and carries no ReadAuthority. Human-
endpoint ceremonies require a human principal and nonzero endpoint generation;
the dispatcher/store still verify the actual installed endpoint and enrollment.
Session rows reject ProofUse, TicketUse and ApprovalUse rather than consuming
them. UploadBegins and blob.commit Objects must have ACL.Config equal to Scope's
configuration and ACL.Owner equal to its authenticated Actor. A lane's ordinary
upload authority remains its own current grants; it cannot mint another human's
or configuration's object. These are structural checks in addition to the live
store authorization, hash/provenance and upload ownership checks.

| Public method | StateWrites fields | Submitted event kinds | Effect payloads | Additional guard / invariant |
| --- | --- | --- | --- | --- |
| blob.begin | UploadBegins | none | none | human S; current bounded upload owner |
| blob.chunk | UploadChunks | none | none | human S; upload generation/contiguous bytes |
| blob.commit | UploadCommits, Objects | blob.committed | none | human S; actual bytes/hash/class/ACL |
| human.challenge | Challenges | human.challenge | none | human endpoint, enrolled principal |
| human.confirm | Challenges, Counters, Proofs, Objects | human.confirmed | none | exact proof-referenced private assertion evidence, verified assertion and challenge/counter CAS |
| human.session | ReadSessions | human.session | none | P; exact live human connection |
| ticket.issue | Tickets | ticket.issued | none | P; issuer/config/endpoint retained |
| grants.root | Grants | grants.issued | none | P; actual root ceiling |
| grants.revoke | Grants, Lanes, Continuations, Endpoints | grants.revoked, lane.stopping, watchdog.cancelled, identity.revoked | Stop | current parent/human, grant CAS, C |
| grants.test-child | WorkerLeases | none | Worker | current parent, bounded child grants |
| lane.start | Lanes, Grants, Turns, WorkerLeases | lane.created, grants.issued | HelperAllocate, Worker, Launch, PlanLaunch | absent life, subset or human T, C |
| lane.adopt | Lanes, Grants, Turns, WorkerLeases | lane.adopted, grants.issued | HelperAllocate, Worker, Launch, PlanLaunch | verified import, absent life, subset or human T, C |
| lane.resume | Lanes, Turns, Continuations, WorkerLeases | lane.turn, watchdog.cancelled | HelperAllocate, Worker, Launch, PlanLaunch | life CAS, cancelled old intent, C |
| lane.turn | Lanes, Turns, Continuations, WorkerLeases | lane.turn, watchdog.cancelled | HelperAllocate, Worker, Launch, Deliver, PlanLaunch | life/turn CAS, authentic mail, C |
| lane.stop | Lanes, Continuations | lane.stopping, watchdog.cancelled | Stop | life CAS, epoch increment |
| lane.mark | Lanes, Continuations | lane.state, watchdog.cancelled | Stop | reviewer receipt, life CAS, epoch on terminal state |
| lane.review | none | lane.reviewed | none | authentic reviewer and complete evidence |
| lane.clean | Lanes, Continuations | watchdog.cancelled | Clean | life CAS, verified archive, no premature cleaned state |
| lane.archive | WorkerLeases | none | Worker | parent/control, retained archive claim |
| lane.check | Lanes | run.observed, lane.lost, lane.ended, lane.state | none | actual current containment measurement; natural completion may move the projection to verifying |
| lane.loop | Lanes | lane.loop | none | current control, life CAS |
| lane.input | WorkerLeases | none | Worker | current attach/control and exact bounded input |
| mail.send | Mail, WorkerLeases | mail.queued | Deliver, Channel | current relation/channel, C |
| report.submit | Mail, WorkerLeases | report.submitted, mail.queued | Deliver, Channel | authentic direct report line, C |
| policy.evaluate | none | policy.evaluated | none | human S; current own policy; never Policy/Decisions |
| guidance.select | none | none | none | human S; unique ReserveGuidance; result via guidance_complete |
| judge.ask | none | none | none | human S; current scoped preview; audit via judge_evaluate |
| org.bootstrap | none | none | Bootstrap | P, absent org; publication via org_bootstrap |
| org.change.propose | Changes, WorkerLeases | org.change.proposed | Worker | L6, exact source/derived staged manifest |
| org.change.approve | Approvals | org.change.approved | none | P, exact manifest/base |
| org.change.apply | none | none | ApplyChange | L6 + A + org CAS; Deferred only, final ChangeReceipt via claimed org_publish completion |
| secret.stage | none | none | none | S; current human read connection, protected encrypted staging |
| secret.import | none | secret.imported | none | P, protected broker transaction |
| secret.rotate | none | secret.rotated | none | P, version CAS, protected broker transaction |
| secret.revoke | none | secret.revoked | none | P, version CAS, protected broker transaction |
| records.append | none | record.appended | none | own observation/report only; human P |
| decisions.mutate | Decisions | decision.changed | none | P, canonical record CAS; supersession appends history |
| records.import | WorkerLeases | none | Worker | collection ACL, confined parser; no current authority from legacy claims |
| store.rebuild | none | none | Rebuild | P, verified frozen snapshot; migration_apply repair completion |
| box.launch, box.run, box.harvest, box.end | WorkerLeases | box.changed | Worker | current resource capability, CAS, actual provider receipts |
| migration.apply | Deployments | none | Migration | P, approved plan and freeze/backup phases |
| upgrade.apply | Deployments | none | Upgrade | P, approved plan and freeze/backup phases |

Policy and OrgSnapshots are never public writes. Grants, JudgeAudits, Channels
and WorkerLeases are explicit StateWrites projections. JudgeAudits come only
from judge_evaluate completion. Channels come only from the approved
org_publish/org_bootstrap generation. WorkerLeases are minted/claimed by the
authorized worker/job operation, bound to operation/effect/grants/expiry; a
public WorkerLeases row never lets a caller supply one over RPC. Internal
effect_complete is restricted to the common measured completion row below.
Completion that writes org/policy/decision/channel/judge state uses the original
specific InternalKind from the persisted effect, with its current claim and
retained approval/proof causality; it cannot use the generic completion kind to
write those projections. The store independently compares the supplied intent
with that actual immutable effect/claim, including actor and original requester.

The permitted InternalKind emitters/effects are closed as follows. These are
trusted in-process or authenticated leased-worker calls; a public endpoint
cannot submit InternalIntent, Scope or StateWrites. A public actor/source label
is never a substitute for that provenance.

| Internal kinds | Bound emitter and permitted effect/projection |
| --- | --- |
| policy_refresh | service/store current-policy coordinator; only the current live Lane policy projection and lane.policy under life CAS/cancellation, with no new approval, grant or launch authority. |
| launch_plan | lifecycle planner under the service outbox's current PlanLaunch claim; LaunchPlans, Grants, Objects, WorkerLeases and launch.planned, grants.issued, capture.bound, capture.refused only. |
| helper_allocate | lifecycle/admin service operation; exact new lease and HelperAllocate effect/lease outcome, helper.allocated only. |
| helper_register | lifecycle/admin service operation; exact immutable spec registration for the lease, nonexecuting, no root selector. |
| helper_prepare | lifecycle/admin service operation; HelperPrepare for the exact registered lease/spec, nonexecuting prepared outcome only. |
| helper_open, helper_stop, helper_abort | lifecycle/admin service operation; exact gate permit/stop or HelperAbort, distinct causal process/nonexecuting abort outcomes. |
| helper_release | lifecycle/admin service operation; HelperRelease for the exact lease after helper-verified quiescence, release only; helper.released carries ReleaseReceipt. |
| effect_complete | service outbox reconciler with the current effect claim; only that measured outcome and causally assigned completion events. |
| mail_deliver | messaging/lifecycle delivery claim; current recipient/turn and mail generation/prompt receipts. |
| guidance_complete, guidance_recover | guidance service; the unique retained turn claim's result or explicit unavailable completion. |
| profile_continue, profile_cancel | lifecycle/watchdog; durable life epoch, continuation claim, bound slot and current eligibility. |
| org_publish, org_bootstrap | approval/templates plus pinned publisher; Applications, Changes, OrgSnapshots, Policy, Grants, Channels and approved Decisions only for the exact approved generation or absent baseline and its completion marker; org.change.applied/org.bootstrapped. |
| upgrade_apply, migration_apply | distribution/migration coordinator (or service frozen-snapshot rebuild); Deployments and the approved durable plan/freeze/backup phases, never a lane lease. |
| capture_append | outside lifecycle capture supervisor; exact run/stream/offset and protected capture provenance. |
| object_retain | templates, judge, grants/dataworker or records component; screened class-specific immutable output under the parent operation. |
| judge_evaluate | scoped judge worker; JudgeAudits and judge.completed with actual resolved context, retained request, budget reservation and provider audit. |
| lifecycle_effect | lifecycle service/scheduler; current life/turn/CAS and explicit launch/stop/clean intent, preserving actual requester. |
| channel_receive | messaging/records fixed intake lease; enrolled source and deduplicated inert message/sheet evidence, never human approval authority. |
| admin_enroll | fixed administrator ceremony; absent enrollment baseline or separately approved current-key change. |

Both public and internal rows are enforced by ValidateTransactionShape, including
internal event/effect and guard discriminants. For the internal table, `C` means
Cancellation, `A` Approval and `P` Proof; none also means no new guard is consumed.
Retained original human authority is checked separately against the parent
operation, not re-consumed by a completion. Public Proof/Ticket guards require
a human actor; human spawn requires Ticket and org.change.apply requires Approval.
TicketUse's principal/config/endpoint must match the authenticated Scope. Each
ticket.issue write also carries that same principal/config/nonzero endpoint;
Ticket, StateWrites.Tickets, IdentityStore.Ticket and ticket.issued/redeemed all
retain the three fields, so rebuilding does not guess the issuing endpoint.
In particular, org_publish, upgrade_apply and migration_apply completion rows
permit Cancellation only. Retained approval provenance is checked against the
parent operation's receipt and consumed guard, never resubmitted as ApprovalUse.
Internal transactions carry neither Reply nor Deferred. The internal branch
checks that union before any internal writes; only CompleteEffect may attach a
deferred final reply from EffectOutcome.Reply in its atomic commit.

The exact internal field/event catalog is below. Its Effect payload set is the
payload/kind pairing paragraph that follows, restricted to each row's operation;
the complete executable rows, including those payloads, are in write_catalog.go.
No unlisted field/event/guard is permitted. These are store integrity rules,
never command/tool permission lists or a substitute for current authorization.

| InternalKind | StateWrites fields | Event kinds | Guard types |
| --- | --- | --- | --- |
| launch_plan | LaunchPlans, Grants, Objects, WorkerLeases | launch.planned, grants.issued, capture.bound, capture.refused | C |
| policy_refresh | Lanes | lane.policy | C |
| helper_allocate | none | helper.allocated | C |
| helper_register | none | none | C |
| helper_prepare | IdentityBindings, Endpoints, LaunchPlans, Lanes, Turns | launch.prepared, identity.bound, lane.created, lane.adopted | C |
| helper_open | Lanes, Endpoints, Turns, IdentityBindings, WorkerLeases, LaunchPlans | lane.started, lane.resumed, lane.turn, runner.session, prompt.observed, identity.bound, data.materialized, secret.injected, credential.leased | C |
| helper_stop | Lanes, Endpoints, Continuations | run.observed, lane.ended, lane.lost, lane.stopping, identity.revoked, credential.released, watchdog.cancelled | C |
| helper_abort | Endpoints, IdentityBindings, LaunchPlans | launch.failed, identity.revoked | C |
| helper_release | none | helper.released, credential.released | C |
| effect_complete | Lanes, Endpoints, IdentityBindings, Turns, Continuations, Mail, Deliveries, WorkerLeases, Objects, Deployments | operation.accepted, operation.completed, operation.failed, worker.completed, worker.failed, launch.prepared, launch.failed, lane.started, lane.resumed, lane.ended, lane.lost, lane.cleaned, archive.verified, helper.allocated, helper.released, data.materialized, credential.leased, credential.released, secret.injected, blob.committed, channel.delivered, channel.failed, mail.delivered, mail.returned, box.changed | C |
| mail_deliver | Mail, Deliveries, Turns, WorkerLeases | mail.delivered, mail.returned, channel.delivered, channel.failed, prompt.observed, lane.turn, secret.injected | C |
| guidance_complete, guidance_recover | Guidance, Turns | guidance.selected | C |
| profile_continue | Lanes, Turns, Continuations, WorkerLeases, Endpoints, IdentityBindings | watchdog.limit, watchdog.waiting, watchdog.swapped | C |
| profile_cancel | Lanes, Continuations, Endpoints | watchdog.cancelled, lane.stopping, identity.revoked | C |
| org_publish | Applications, Changes, OrgSnapshots, Policy, Grants, Channels, Decisions, Objects, WorkerLeases | org.change.applied, record.appended, decision.changed, blob.committed | C |
| org_bootstrap | OrgSnapshots, Policy, Grants, Channels, Decisions, Objects, WorkerLeases | org.bootstrapped, record.appended, decision.changed, blob.committed | C |
| upgrade_apply | Deployments, Objects, WorkerLeases, Endpoints | upgrade.applied, worker.completed, worker.failed, blob.committed | C |
| migration_apply | Deployments, Objects, WorkerLeases | migration.completed, record.appended, worker.completed, worker.failed, blob.committed | C |
| capture_append | Objects | capture.appended, capture.gap, capture.closed, runner.session, prompt.observed | C |
| object_retain | Objects, WorkerLeases | blob.committed, worker.completed, worker.failed | C |
| judge_evaluate | JudgeAudits, Objects | judge.completed, blob.committed | C |
| lifecycle_effect | Lanes, Grants, Turns, Endpoints, IdentityBindings, Continuations, WorkerLeases | lane.created, lane.adopted, launch.prepared, launch.failed, lane.started, lane.resumed, lane.turn, prompt.observed, lane.stopping, lane.ended, lane.lost, lane.state, lane.cleaned, lane.reviewed, lane.loop, run.observed, grants.issued, grants.revoked, identity.bound, identity.revoked, data.materialized, secret.injected, credential.leased, credential.released, runner.session, watchdog.cancelled, archive.verified | C |
| channel_receive | Mail, Deliveries, WorkerLeases, Objects | record.appended, mail.queued, report.submitted, channel.delivered, channel.failed, worker.completed, worker.failed, blob.committed | C |
| admin_enroll | Enrollments, Objects | blob.committed | P, A |

channel_receive and migration_apply record events retain inert observation/
legacy provenance; they cannot create canonical decisions through a collection
label. The store validates payload class/provenance against the actual source.

For every Effect, Context is a catalogued InternalIntent with the same config,
effect ID and causal operation ID. Its payload/kind pairing is closed:
HelperAllocate/helper_allocate, HelperPrepare/helper_prepare,
HelperRelease/helper_release, HelperAbort/helper_abort;
PlanLaunch/launch_plan selects only the retained reservation;
Launch/Stop/Clean use lifecycle_effect; Swap uses profile_continue;
Deliver/Channel use mail_deliver; Worker uses lifecycle_effect, object_retain or
channel_receive; ApplyChange uses org_publish; Bootstrap uses org_bootstrap;
Migration/Rebuild use migration_apply; Upgrade uses upgrade_apply. Helper
payload Cause equals Context (abort's explicit IDs must also agree). OpenGate /
StopGate / RegisterSpec subcalls use their own correlated helper kind within the
parent effect; none relabels release as abort. ValidateTransactionShape checks
this before the store's current authority and provenance checks.

ObjectMetadata returns the actual committed class/length/hash/ACL/provenance.
Caller BlobRef class labels are not trusted; records now checks metadata before
screening bytes. Upload begin/chunk/commit writes retain the bounded lease,
owner, contiguous bytes/hash and 15-minute expiration atomically. RetainObject
is a trusted component operation for prompt/render/judge outputs with an
InternalIntent and real input refs, never a public provenance-class override.
ObjectACL binds config, owner/life, audience, participants and generation;
service/capture/policy/archive/approval classes require their trusted emitter.
Blob read at the exact end returns empty bytes and their real empty-byte hash;
it permits oversized-prefix reference detection without pretending a truncation
is complete. Secret material remains outside generic objects/events/frames.

BeginRead returns a pinned ReadView, carried internally in Scope. All reads in
that handler use the same snapshot; Response.last_seq is its actual LastSeq,
or the actual mutation commit sequence. Zero means a genuinely empty head.
Close the read view after the initial stream snapshot; live delivery uses fresh
authority checks and bounded cursors. Client.Stream exposes ResponseStream's
Initial response before frames. No lost snapshot, guessed sequence or EOF-as-end.

### Sources, D6, briefing and canonical decisions

OrgSnapshot is configuration/org/generation bound and contains the complete
source/derived inventory, modes, hashes, ownership manifest and service-pinned
renderer. Org generation is distinct from policy generation. TemplateSources
resolves exact (level, role) against that approved snapshot: LocalStatus is
absent or present. Unreadable/malformed/stale/wrong-role is a typed error, never
absence. SourceRef.ID is an approved source identity; Source resolves it to an
actual committed content ref with exact digest/generation, not a host path.
SourceRef.Generation is the current snapshot generation; ResourceFile separately
retains the original RevisionGeneration for unchanged file history.

ConfigView.Projection is a committed `laneboss.config-view.v2` ConfigProjection.
Its view is the existing closed list, show, path, settings, roles, channels, plugins
catalog. SettingValue has exactly one typed value and its defining source; it
is screened and contains no secret or ambient environment dump. Logical binding
metadata may be shown for path; writable state directories are not exposed.

ChangeRequest now retains Config, Reason, SourceSnapshot and OwnershipManifest
in addition to the renderer pin. Propose verifies actual ownership/before
hashes/modes and renders in the confined worker before returning the exact
source-plus-derived staged manifest. Approve retrieves CheckProof's real key/
nonce facts and commits ProofUse with the approval/reply. Apply reserves the
matching ApprovalUse and org/base generation under the per-org apply lock.
OrgPublisher publishes a verified immutable generation and atomically swaps its
approved pointer; the filesystem commit marker binds operation, manifest and
renderer. Store completion reconciles that marker after a crash. During an
unfinished publication the org's dispatch/read gate cannot expose mixed DB/FS
generations. A different manifest/base requires a fresh approval. No successful
ChangeReceipt is returned merely because an outbox item was queued.

Bootstrap uses absent-org CAS, verified human proof, a pinned confined renderer
and BootstrapEffect/BootstrapReceipt through the same publication machinery.
Existing orgs refuse and use D6. BriefingInput resolves the retained original
task, reserved/current life/workspace/lineage, grants, policy, sources and groups.
For lane/worker scopes, TemplateRequest.grant_set_id must equal the caller's
current Lane.grant_set_id and BriefingRequest.life_id must be empty or its own
life. BriefingInputRequest IDs are checked claims, never selectors for a
different life/grant set; mismatches are forbidden before any selected-object
store read. Resolve the input from the authenticated scope first. Role/level
claims must also agree with that authentic life.
A human overview with no life/task remains read-only and claims no launch.
Lane and LaunchEvent retain Task/LaunchID; TurnSnapshot/TurnEvent retain the
actual task and prompt association. Lifecycle uses the exact retained prompt
and records delivery observation separately from preparation.

DecisionCandidates returns only authoritative, applicable active decisions,
with service-derived DecisionAuthority, effective time and scope. Proposals and
legacy history are not promoted by JSON Binding/actor labels. DecisionDocument
is the versioned structured content; old plain text remains a nonbinding
configuration-scoped canonical reminder only after a real human/D6 commit.
Binding policy/grants still change only through their proper approval paths.
DecisionProjection retains active/superseded/proposal status and provenance.
Structured content has schema `laneboss.decision.v2`, nonempty screened Text,
an RFC3339 EffectiveAt and bounded AppliesTo (at most 200 total entries; levels
3–6 and valid role/project/life IDs). Object/array-looking malformed content
refuses rather than falling back to plain text. Screen the decoded text too.
Plain text has Binding=false, configuration-wide empty applicability and the
committed record's effective time. Authority.Kind is human with the verified
ProofRef ID, or d6 with the approved change receipt/org generation; store stamps
the actual decision.changed SourceSeq. A caller cannot supply those facts.
DecisionsMutate writes Decisions together with the matching history events and
exact reply. `TurnStore.Decision(ctx, scope, recordID)` reads the retained scoped
projection, including superseded history, to preserve its original authority.
Supersede allocates a new record ID/generation 1 linked by SupersedesID and
RelatedIDs to the old record. In the same transaction it appends a second
decision.changed version marking the old record Action=superseded and advancing
its generation, retaining its original Content/Actor and candidate authority.
Both old-record CAS and new-record absent CAS apply atomically; old event bytes
are never changed. Annotation/feedback append only metadata references under
CAS and preserve canonical content/candidate/status. Replay lookup occurs
before content/projection/bounded-metadata preflight, including the 200th entry;
an identical retry returns its original reply, not a rejected 201st append.
Before lookup, records checks a human ProofRef's valid ID and exact intent digest
and refuses any ProofRef on a lane scope. It checks MutationReceipt.Config, Key
(method/key/digest) and Actor's kind/principal/life after both LookupReceipt and
AwaitReceipt, returning integrity on a foreign receipt. MutationReceipt.Config
is retained store metadata, not inferred from the current caller. The receipt
domain is config/principal/life/method/key; fixture storage uses that same domain.
Replay still precedes proof consumption/CAS, so the already-used nonce is not
verified or consumed again. Annotation/feedback Record.RecordedAt is the new
metadata mutation time; candidate EffectiveAt and its original authority stay
fixed, and replay returns the original metadata timestamp.
DecisionQuery.kind is binding or reminder; both page against one immutable
snapshot. Every current binding decision/approval/blacklist is retained
separately from ranked reminders. Complete=true means the actual end, and
unavailable/incomplete storage is an error, never an empty successful corpus.

### Logical turns, judgments and quota continuation

Guidance resolves TurnSnapshot's actual task; GuidanceRequest.Task is an exact
claim to check, not a choice of another visible input. ReserveGuidance uniquely
claims (config, life, logical turn) across request keys/restarts/profile swaps,
retaining task/hash, policy and candidate snapshot, deadline and claim. Only
the winning claim judges; pending callers await/replay. An interrupted/expired
claim completes a visible unavailable receipt without an independent rejudge.
The five-second total budget starts on entry before store/queue wait and its
deadline never resets. Guidance status is scored, empty or unavailable; minimum
relevance defaults to 0.50 and the configurable scalar/source comes from the
approved EffectivePolicy. Binding context never consumes the five reminder slots.

ScopedJudge validates actual scope/turn/grants/policy and audits the raw Judge
provider calls. Policy/guidance depend on ScopedJudge; raw provider labels grant
nothing. JudgeReply.Request and JudgeAudit retain authorized exact request-byte
references; records.get/blob.read expose them only through normal ACLs.
ScopedJudge resolves EffectivePolicy.Judge at Scope.PolicyGeneration and uses
ResolveJudgeForScope to refuse a differing JudgeRequest.Config or stale context
generation. It selects the matching Clef/TypeSafe port after that resolution.
It resolves both request and policy configurations before comparing, so R108's
empty provider/model spelling equals the explicit default with identical pins.
ResolveJudgeConfig refuses Clef without lowercase 64-hex deployment/tokenizer
digests and ContextTokens > 0. R108 still supplies only the provider/full model
defaults; it invents no deployment pins. Installation entries enroll capability,
not an override of approved policy. Missing enrollment or outage never falls
back to the other provider.
Guidance.JudgmentIDs contains every batch receipt; JudgmentID may identify their
aggregate. Batches preserve every question, task, fit, model, deployment, cost, result
and total deadline; no silent first-twelve truncation. JudgeRequest already has
Rules and Decisions arrays in the freeze, so no speculative replacement is
needed for the expected judge2 batch request. Its exact later request, if any,
must be reconciled with this revision. R108 remains the decided default.

Watchdog no longer acquires a replacement slot before Continue. It validates
the limit, current grants/room and typed ProfileEligibility, then submits
ContinuationRequest with expected life generation, cancellation epoch and the
durable intent. Lifecycle atomically claims that intent under the same per-life
serialization used by manual control/revocation, acquires exactly one eligible
slot and persists its handoff before opening the next gate. Restart resumes or
collects that same slot; it never calls Acquire blindly again. Stop/abandon/
clean/revocation increment the durable epoch and cancel outstanding claims.
Continue rechecks driver/provider/model/session/history and exclusions through
broker eligibility and current grants. No paid fallback or budget reset.
Lane.Counters, CancellationEpoch and Session.HistoryID expose actual invariants
without private paths. Logical turn/task/history/mail stay fixed; only run/slot
advance. ProfileGrant choice/eligibility/generation/epoch are retained in the
ProfileSwap/continuation receipts, not parsed from reason strings.
ContinuationRequest has only IntentID and Swap; Swap is the sole submitted
copy of ExpectedGeneration, CancellationEpoch and EligibilityID. Lifecycle
compares it with the stored ContinuationIntent under the life lock. The stored
intent's own fence/eligibility and Swap must agree; disagreement is invalid_request.
Lifecycle derives LogicalTurnID, CausingRun and ContinuationRun from the durable
life and refuses submitted values that differ. Eligibility is incompatible when
the destination grant is paid and the source is not, ToGrantID is outside the
current GrantSet.Profiles, or ToProfileID is in EffectivePolicy.ProfileExclusions.

### Delivery, legacy intake and deployment

EnrolledChannel resolves current destination IDs, transport, generation,
credential handles and delivery semantics from protected org sources.
ChannelJob is one destination and one durable WorkerLease/effect/provider key.
The internal channel mode accepts a protected lease reference, verifies its
installed worker endpoint/UID/job binding, claims it once and runs only the
fixed installed worker in its grants. InjectWorker supplies only the selected
names/version/delivery for that lease; no host credential inheritance. Worker
credential handles/versions must already be authorized by the lease's grant set
or that enrolled channel's credential handles; the caller's list selects among
those entries and never adds one. InjectWorker refuses every unmatched entry.
Worker kinds additionally include channel, owner_sheet and gateway; none is an agent
driver. Confirmed per-destination deliveries deduplicate. An uncertain send is
reconciled by provider key/read-back, or stays uncertain when the provider has
no such capability; it is never blindly retried as a new message.

MailForTurn is a service-only lease-bound read. Relation returns only authentic
relation metadata, not sibling private task/session/logs. Public Lane/Mail ACLs
are unchanged. BeginDelivery rechecks every sender, relationship, current grant,
recipient/turn and cancellation epoch; RecordDelivery commits the correlated
capture/prompt observation with mail generation CAS through an internal intent.
A profile-limit process end cannot acknowledge mail. Real manual/scheduler
actor remains separate from each carried sender. Mail retains Artifacts and
Generation; ReportRequest adds Ask. An answered ask retains a DecisionAnswer
and status answered, preserving the original question without inventing a send.
Other statuses remain queued/delivering/delivered/returned.

OwnerIntake consumes an authenticated fixed worker lease and enrolled
channel/sheet identity, not a lane-authored human label. Receive evidence,
remote sender/message IDs and cursors are retained with deduplication; restart
history gaps remain explicit. Sheet bytes/answers/notes/stable IDs remain inert
until verified human decision proof or D6 accepts the exact proposed content.
Gateway or sheet observation cannot approve D6, issue tickets or become ambient
human mutation authority. Integration owns these remaining legacy ports.

EffectStore claims and completes immutable effects by ID/generation/claim,
retaining original causality and real typed outcome. Claim expiry does not prove
a process/send stopped: reconcile before repeating, and keep unknown outcomes
explicit. Completion commits only measured receipts, not the worker's success
text. Awaiting a synchronous result holds no global writer lock.

Distribution implements DeploymentCoordinator using StateStore, DispatchControl,
MigrationAPI and a separate administrator-bound DeploymentInstaller. Plan is
read-only inventory/retention; it does not freeze live work. Apply's human proof
reserves durable phases: planned, freezing, draining, backed_up, staged,
migrating, activating, complete (or failed/uncertain/rolled_back). Persist each
phase and operation before its effect. Freeze stops dispatch/watchdog; drain
requires actual capture/effect/process quiescence. FrozenBackup binds matched
old state/config/release and verified recovery evidence. Stage verifies uploaded
service-issued handles against offline source/vendor/executable digests;
offline content labels are never live handles. Migration runs once under that
plan; activation/read-back swaps coherent bindings only after the preceding
phase succeeds. Keep old bytes until verified process exits. Rollback retains
new history/work first, then restores matched old executable/state/config.
Canonical org changes additionally use D6. Lane HelperLease grants no deployment
authority. ObjectAssembly supports an ordered manifest of individually bounded
parts for a file larger than 64 MiB; verify total size and concatenated digest
in the confined worker before installation, with no oversized-object exception.

### Harness controls and rebase matrix

The harness context may add optional `controls` naming an absolute protected
control-binding file. It is an E2E-owned protocol, never a product RPC, CLI
bypass or auth token. Its closed actions are restart_service,
run_confined_canary and advance_fixture_clock. Requests bind case/phase/artifact,
operation ID, independently random nonce and uploaded canary/clock input;
responses retain exact observed exit/containment/restart/capture facts and hashes.
The independent controller authenticates the harness process/scope and owns
the actual unit/cgroup/action. Cases cannot guess a unit, shell into a service
UID, choose arbitrary commands, sign in or turn fixture clocks into live policy.
Absent controls fail the dependent row; setup/hardware/live cells remain distinct.

The closed binding/request/response maps are frozen in the integration case's
control.schema.json. Transport uses the same bounded four-byte-length framing,
with protected file ownership and actual controller/case peer credentials; it
is a separate harness endpoint. Every nonce/request/artifact/case must match.
Only pre-enrolled service/canary/fixture-clock IDs are selectors. Restart must
observe the old PID's exit and the new generation, rather than return a claim.
Canary execution is a fixed registered job confined to the selected child's
current grants, with actual exit/containment/input/output evidence; unknown
containment cannot be serialized as a successful zero-survivor result.
Clock control affects only a registered injected fixture Clock, never OS time
or a live-auth deployment. These controls authorize no authentication, paid
requests, machine provisioning or arbitrary host command. E2E owns the real
controller/discovery implementation and independently verifies all evidence.

The following table records the draft.3 consolidation. Draft.4 consumers also
apply §15 on top of the supervisor-landed draft.3 change set at 94b2cc9.
Integration cannot name a draft.4 commit until laneboss stages/reviews/commits
it. Do not cherry-pick just api.

| Request / supplied source | Consumers and required port |
| --- | --- |
| Darwin 4e9cf95 | darwin, linux, admin, identity, lifecycle, grants, secrets, both runners, service/client, assembly, packaging: HelperControl, RuntimeResolver, ContainmentRegistry, BindLaunch tuple and installed backend/doctor composition. |
| Identity 3b14e7c | identity, both peers, admin, service/store/client, dashboard, lifecycle and every human mutation owner: connection/frame/read lifetime, enrollment, AuthorizationTarget, CheckProof plus atomic guards, ticket/counter writes and common request sealing. |
| Approval slice 1 | approval, service/store, identity, grants/dataworker, templates, policy, dashboard: snapshots/ownership, exact reply lookup before preflight, proof facts and OrgPublisher completion. |
| Guidance 0ad4625 | guidance, service/store, records, lifecycle, messaging, judge, templates, dashboard, E2E: authoritative paged candidates, turn/task source, unique reservation, scoped judge/audit and retained text. |
| Templates bfe42d3 | templates, service/store, policy, approval/dataworker, lifecycle, identity, dashboard, packaging/E2E: approved sources, object metadata/retention, briefing input and atomic bootstrap. |
| Watchdog 567a8c4 | watchdog, lifecycle, secrets, claudock, service/store, messaging, dashboard/E2E, assembly: durable epoch/claim, lifecycle-owned slot acquisition, typed eligibility, history/counters and constructor inputs. |
| Messaging ced9d34 | messaging, lifecycle/watchdog, service/store, approval, admin/isolation, secrets, records, dashboard/CLI, migration/E2E: channel/job leases, delivery receipts, relation-only reads, artifacts/ask and current blob/sequence semantics. |
| Service 54e4f51 | service/store/client, identity, all mutation/read owners, admin, both launchers, assembly, dashboard/E2E: binding bytes, receipts/guards/objects/effects/CAS, pinned read head, ResponseStream and harness control contract. |
| Admin fbe0aae | admin, linux/darwin, identity, lifecycle, grants, service/store, assembly/packaging: protected spec/runtime/network handoff, fixed gate control, causal completion and nonexecuting abort. |
| Packaging 8fd6394 | packaging/distribution, service/store, lifecycle/watchdog, migration, admin, assembly, both runners/E2E: durable deployment plan/phases, verified backup, separate installer/coordinator and part assembly. |

The contract review must reconcile each supplied note against these signatures
and the acceptance deltas above. Implementing the ports remains each owning
lane's work; remove/replace its contract_stubs only with real implementations
and positive/red Linux evidence. No interface-only error removal is acceptance.

### Draft.3/draft.4 additional tagged objects

These are exact tagged field maps for new retained/public JSON objects. The
untagged state/effect/identity interfaces above are service-internal Go objects,
not additional RPC bodies. Internal handles never serialize into Scope.

| Object | Exact fields |
| --- | --- |
| `ConfigProjection` | `{schema: string, config: string, view: string, generation: integer, context?: RoleContext, names: []string, settings: []SettingValue, resources: []Resource, sources: []SourceRef, binding?: InstalledBinding, warnings: []string}` |
| `DecisionAnswer` | `{decision_id: ID, source: SourceRef, content: BlobRef, authority: DecisionAuthority}` |
| `DecisionApplicability` | `{levels: []integer, roles: []string, project_ids: []ID, life_ids: []ID}` |
| `DecisionAuthority` | `{kind: string, receipt_id: ID, org_generation: integer, source_seq: integer}` |
| `DecisionDocument` | `{schema: string, text: string, effective_at: Timestamp, applies_to: DecisionApplicability, binding: boolean}` |
| `InstalledBinding` | `{schema: string, contract_revision: string, protocol: string, api_schema: integer, config: string, class: EndpointClass, installation_generation: integer, endpoint_generation: integer, service_uid: integer, service_gid: integer, mapped_service_uid: integer, mapped_service_gid: integer, socket: string, artifact_sha256: Digest, service_version: string, backend: string, launch_id?: ID, target?: LifeRef, worker_lease_id?: ID}` |
| `ObjectAssembly` | `{sha256: Digest, bytes: integer, parts: []BlobRef}` |
| `OrgSnapshotRef` | `{org_id: ID, generation: integer, manifest_sha256: Digest}` |
| `ProofUseReceipt` | `{proof_id: ID, credential_id: ID, nonce_id: ID, operation_id: ID, used_at: Timestamp}` |
| `RuntimeManifest` | `{schema: string, generation: integer, artifact: Executable, bootstrap: Executable, objects: []RuntimeObject, bindings: []InstalledBinding}` |
| `RuntimeObject` | `{id: ID, role: string, root_id: ID, relative_path: string, content: BlobRef, mode: integer, aliases?: []string}` |
| `SettingValue` | `{key: string, boolean?: boolean, integer?: integer, string?: string, strings?: []string, source: SourceRef}` |
| `TaskCounters` | `{failures: integer, retries: integer}` |
| `InternalIntent` | `{id: ID, kind: InternalKind, config: string, actor: Actor, requested_by: Actor, cause_operation_id: ID, cause_request_id: ID, effect_id: ID, target: LifeRef, logical_turn_id: ID, cancellation_epoch: integer}` |
| `PreparedSpecHandoff` | `{cause: InternalIntent, config: string, spec: LaunchSpec, original: BlobRef, spec_sha256: Digest, operation_id: ID, request_id: ID}` |
| `PreparedSpecReceipt` | `{spec_id: ID, config: string, target: LifeRef, lease_id: ID, spec_sha256: Digest, runtime_manifest: BlobRef, operation_id: ID}` |
| `HelperOpenRequest` | `{cause: InternalIntent, prepared: PreparedLaunch, permit: LaunchPermit, operation_id: ID, effect_id: ID}` |
| `HelperObserveRequest` | `{lease_id: ID, handle: ProcessHandle}` |
| `HelperStopRequest` | `{cause: InternalIntent, target: HelperObserveRequest, reason: string, operation_id: ID, effect_id: ID}` |
| `HelperAbortRequest` | `{cause: InternalIntent, lease_id: ID, prepared_id: ID, spec_sha256: Digest, operation_id: ID, effect_id: ID}` |
| `HelperReleaseRequest` | `{cause: InternalIntent, lease_id: ID, observation: ProcessObservation}` |
| `ReleaseReceipt` | `{id: ID, lease_id: ID, containment_id: ID, backend: string, operation_id: ID, effect_id: ID, quiescence: ProcessObservation, live_connections: integer, queued_jobs: integer, writable_exports: integer, observed_at: Timestamp}`; a success requires every measured count, including quiescence.survivors, to be known zero. |
| `AbortReceipt` | `{id: ID, lease_id: ID, prepared_id: ID, agent_executed: boolean, quiescence: ProcessObservation, observed_at: Timestamp}` |
| `HelperReconcileRequest` | `{lease_id: ID, launch_id: ID, prepared_id: ID, operation_id: ID}` |
| `LaunchReconciliation` | `{prepared?: PreparedLaunch, process?: ProcessHandle, observation: ProcessObservation, gate_state: string, consumed_permit?: LaunchPermit}` |

## 15. Draft.3 → draft.4 correction ledger

The base is the supervisor-landed draft.3 at `94b2cc9`; the rest of §14 remains
in force. Rebase only these corrections with the complete reviewed integration
change set. This is a contract/static checkpoint, not runtime acceptance.

| Exact change since draft.3 | Consumers that adapt |
| --- | --- |
| Authenticator.Authenticate takes ConnectionContext; PeerVerifier.Verify additionally takes InstalledBinding. ConnectionContext adds Conn, BindPeer and BindReadAuthority. | service transport, identity, Linux/Darwin peers and dashboard connection contexts; assembly keeps per-connection binding selection with identity. |
| Helper.Release returns (ReleaseReceipt, error). EffectOutcome adds Release; helper.released payload changes from HelperLease to ReleaseReceipt. | admin, Linux/Darwin launchers, lifecycle, service/store completion and packaging/harness fixtures. |
| InternalHelperRegister/Prepare/Release added. PreparedSpecHandoff, HelperOpenRequest, HelperStopRequest and HelperAbortRequest add Cause; abort adds EffectID. Listed helper IPC DTOs gain exact snake_case tags. | admin, launchers/runtime resolver, lifecycle, service/store and helper fixtures. No new public helper RPC. |
| StateWrites adds Grants, JudgeAudits, Channels, WorkerLeases; public writes/events/effects now have an explicit matrix and shape check; mutations require Reply. | service/store, every mutation owner, grants, judge, approval/templates, messaging, workers and E2E. Record projection still derives from its events. |
| TurnStore adds Decision(context.Context, Scope, ID) (DecisionProjection, error). DecisionsMutate validates documents and preserves append-only supersession/history. | service/store, records, guidance/dashboard projection consumers, migration/approval decision imports. |
| TicketUse adds PrincipalID, Config and EndpointGeneration; human-class root-ticket rule and own-life briefing claims are explicit. | identity, lifecycle, service/store, templates and dashboard/CLI fixtures. |
| ContinuationRequest removes its outer ExpectedGeneration, CancellationEpoch and EligibilityID; use Swap only. | watchdog, lifecycle, secrets eligibility, service/store and continuation fixtures. |
| ResolveJudgeConfig requires Clef pins; ResolveJudgeForScope pins request config to approved policy. judge.Dependencies.Provider becomes Clef and TypeSafe. Installation adds optional JudgeAlternative enrollment. | judge, policy, guidance, assembly, admin/packaging boot files and judge fixtures. R108 default is unchanged. |
| PrepareRequest refuses empty mutation keys. Invocation shares its socket; human-read --proof establishes human.session there. Records/decisions accept --content-ref for proof-bound input. | service/client, every CLI feature owner and all mutation fixtures/scripts; explicit Client means an already-open borrowed connection. |
| Scanner exemption requires this module's tracked package directory/index bytes and clears import context at the actual closing delimiter. Harness result evidence paths reject traversal in all branches. | integration/scanner, supervising staged scan, E2E controller/schema consumers. |
| Scanner hex-segment closure | A long hex-looking suffix has no import exemption unless it is an actual tracked Go package in this module. `nonexistent-own-path` exercises this; scanner and supervising staged-scan consumers retain that restriction. |

### Draft.4 fix 2 review closure

This delta is on the supervisor-tested c17971b baseline. The tests and controls
below are required on the new source; prior green box results do not cover it.
No public method, driver or command/tool policy is added. The exact Ticket
tagged fields are a coordinated unreleased-draft wire change; all matched
service/client/helper artifacts and fixtures consume the updated draft together.

| Review item | Concrete correction and regression | Consumers that adapt |
| --- | --- | --- |
| Gemini 1 / Fable 3: human content/self/tree reads | All non-mutation reads with --proof establish human.session before the read on the shared socket, as does secret.stage. TestContentReadSession and content-read-session control require the session first and no proof on records.get. | common CLI/client, identity/service and dashboard/feature CLI owners |
| Gemini 2: missing lifecycle writes | Public start/adopt/resume/turn include WorkerLeases; resume/turn permit lane.turn and watchdog.cancelled; revoke includes lane/continuation/endpoint cancellation writes/events. TestLifecycleWorkerWrites includes all four worker paths and grant revocation. | lifecycle, grants, service/store, confined workers |
| Gemini 2: internal integrity and public guards | InternalKind now checks fields/events/effects/guard types against internalWriteCatalog; generic completion cannot write policy. Public lane Proof/Ticket guards refuse, human spawn requires Ticket and D6 apply requires Approval. TestInternalWriteAuthority and TestPublicGuardAuthority have deliberate injection/missing-guard controls. | service/store, admin, identity, lifecycle, approval, all internal job owners |
| Gemini 3: ticket provenance | Ticket gains principal_id, config and endpoint_generation, automatically carried by StateWrites.Tickets, IdentityStore.Ticket and ticket events. Issued fields must match Scope. TestTicketProvenance checks wire round trip and wrong issuer/config/endpoint refusal. | identity, lifecycle, service/store rebuild, client/dashboard/E2E ticket decoders |
| Gemini 4 / Fable 2: replay hardening | Validate proof ID/digest and reject lane proofs before replay. MutationReceipt adds Config; records compares retained config/key/principal/life after LookupReceipt and AwaitReceipt without consuming a proof again. TestDecisionProofReplay and TestReplayReceiptBinding cover malformed proofs and foreign backend receipts. This is defense in depth; the specified replay order is preserved. | service/store receipt producers, records and receipt fixtures |
| Gemini 4: metadata time | Annotation/feedback stamp the new Record.RecordedAt while preserving candidate EffectiveAt/authority and original reply on retry. TestDecisionNotesAndCAS plus decision-note-time control verify it. | records, dashboard/guidance metadata consumers |
| Gemini 5 / Fable 1: scanner red setup errors | Read exact retained result rows and scanner stdout/stderr for both modes; red requires self-test exit 1 but actual mutant scanner exit 0 with SCAN PASS. Candidate requires scanner exit 1 with the intended token rule. ScannerVerdictTests and the scanner-verifier mutant reject setup, syntax, missing evidence and missing-mode outcomes. | integration E2E/controller and supervising test-box runner |
| Gemini 6: stale event row | Section 4 now lists ReleaseReceipt for helper.released, matching EventSchemas and §14. TestHelperReleaseEvent and release-event-payload control pin the real type. | admin/helper, service/store, event/rebuild/E2E consumers |
| Fable 4: R108 spelling | Resolve both request and policy JudgeConfig before comparing; empty provider/model equals its explicit default only with identical approved pins. TestJudgePinsApprovedPolicy adds that positive control; unapproved providers/deployments still refuse. | judge, policy, guidance, API clients |
| Fable 5: scoped receipt fixture | Receipt maps use config, actor kind/principal/life, method and key; they retain original receipt metadata rather than rebuilding it from the caller. TestReceiptDomains refuses cross-principal/config/life/method lookups. | records tests and service/store replay fixtures |

The existing unapproved-provider red control now mutates the resolved-config
comparison because the source comparison intentionally changed from raw to
resolved values. Its assertion and diagnostic still require refusal of a D6-
unapproved provider. No control was changed to accept a setup/candidate failure.
Fix 2's runner has 31 Go controls, the verifier's own red/candidate check, and the two
scanner controls (both working and staged); each must retain its actual source,
outputs and reached assertion before the candidate is accepted.

### Draft.4 fix 3 review closure

This delta is on the supervisor-tested 74354cd baseline; new runtime results
remain required. Ticket redemption semantics are confirmed, not broadened.

| Review item | Concrete correction and regression | Consumers that adapt |
| --- | --- | --- |
| Fable P2: unreachable human upload | The catalog marks bounded blob staging and previews as session-scoped. Dispatcher uses WithReadAuthority; Scope.ReadAuthority and ReadAuthority.ConnectionID carry exact internal binding facts. CLI session setup covers these mutations. TestHumanStagingAndAppend stages real bytes through ValidateTransactionShape and the fixture store, then uses production RecordsAppend with one final ProofUse. A missing final proof refuses; TestStagingSessionBinding rejects lane/missing/foreign/expired/closed authority. TestBlobStagingSession pins CLI session setup; TestHumanPreviewSession covers the four other session methods. | service dispatch/store/upload, identity connection/session facts, common CLI, secrets, policy/guidance/judge and dashboard clients |
| Fable P3: ticket issuer vs redeemer | Explicitly retain same principal/configuration/human endpoint generation. Socket changes within that generation are allowed; another principal or rotation needs fresh issuance. TestRootTicketBoundScope and root-ticket-transfer control pin the existing checks. Design basis is isolation.md §4 human-issued tickets and operation-bound approval, cited above. | identity ticket issuance, lifecycle root launch, store redemption/rebuild, dashboard/CLI |
| Combined guidance file-input failure | Common InvokeRaw now calls the method-owned semantic hook after DecodeObject and before proof/key/socket work. RegisterInputValidator pins the method owner and missing hooks fail closed. Production records.get/query/export validators are shared with the service. TestFileInputHook covers guidance class/run/negative/oversize semantics with an explicit adapter fixture (or the combined registered guidance validator), a production records negative, exact code/message/owner, and a positive forwarded request. Two skipped-hook controls require those named failures. The actual guidance adapter must register lbV2GuidanceFileRequest; all other feature adapters register their owned input validators. | all feature CLI owners, common CLI/client, records, combined guidance/approval tests and installed CLI fixtures |
| Approval pending synchronous publication | Add DeferredReply (Key, OperationID, EffectID) on Transaction / Commit / MutationReceipt and DeferredCompletion on EffectOutcome.Reply. Only guarded L6 org.change.apply may defer, with org CAS, original frame/digest/reservation and one causal ApplyChange. CompleteEffect seals the measured ChangeReceipt/Error atomically on that original receipt; ValidateDeferredCompletion refuses a competing final reply or unrelated effect/claim. TestDeferredMutation and TestDeferredCompletion cover successful/failing shapes and missing effect, guard/CAS, foreign binding, premature receipt and second-reply refusals. Two new controls remove the effect requirement and the final-reply check. | approval, service dispatch / store / receipt / outbox / publisher / recovery, templates/bootstrap and other synchronous-mutation owners, common/approval CLI and installed/red fixtures |
| Identity atomic assertion evidence | Permit Objects only on human.confirm, with validAssertionEvidence requiring one exact proof-referenced identity artifact, hash/bytes equal to the verified typed assertion and an exclusive principal/config private ACL. Challenge/counter/proof/event/reply bindings remain in the same transaction. This implements §14 and isolation.md §4's verified operation-bound confirmation without a separate upload or invented retention intent. TestConfirmEvidence accepts the correct handoff and refuses unrelated, altered, extra/missing or exposed evidence and other-method use. Two omitted-binding controls must fail its unreferenced and foreign_owner assertions. | identity confirmation/CheckProof and private evidence readers; service/store atomic identity commit, object ACL/replay/rebuild and installed identity/serve fixtures |

The workflow test starts from an already verified read session; the single
proof counted is the final record operation proof, not the earlier session
authentication ceremony. Its fixture does not skip the production guard:
every staging transaction calls ValidateTransactionShape before storing bytes,
and final append calls records.RecordsAppend. This unit regression workload
leaves WebAuthn/installed-service acceptance to its separate gate. The staging/ticket red controls reintroduce per-blob
proofs, borrow a human session from a lane, reintroduce preview proofs, omit CLI
staging session setup and transfer a root ticket. Four more controls cover both
file-input validators and the deferred-effect/second-reply gates. Two further
controls cover assertion-reference binding and exclusive principal privacy.
Fix 3's runner has 42 Go
controls plus the verifier check and two scanner controls; all must run on the
exact candidate before acceptance.

The deferred data fields and ValidateDeferredCompletion helper are internal
contract additions; no existing port signature or public RPC body changes.
Approval replaces its nil-Reply apply transaction with Deferred and awaits the
same reserved receipt. Service/store implements durable pending/replay/claim/
completion with the existing Transact, ClaimEffect, CompleteEffect and
AwaitReceipt ports. Publisher success must supply its actual publication marker;
CLI must never print the pending Commit as a successful ChangeReceipt. Bootstrap
continues to return its documented Operation and does not gain deferred authority
from the apply row. These consumer adaptations and the original feature suites
are still required; static checks or fixture completion alone do not close D6.

The scanner still exempts only a token match wholly inside the quoted own import
path on a whole import-spec line. go.mod must declare exactly
`module laneboss.io/laneboss`, and the suffix must hold tracked regular .go
files. `--staged` uses its existing ls-files -s listing and indexed go.mod bytes,
not working-tree existence. No other pattern, denylist rule or go.sum exception
changes. The test-box scanner workload has 19 fixtures in working/index modes,
including nonexistent-own-path, delimiter escape, wrong module, untracked
package and deliberately different indexed/working content. It retains real
temporary Git/index inputs and observed scanner outputs; it never stages the
product checkout. Local static checks cannot establish those runtime results.

### Draft.4 fix 5 review closure

This delta starts from a94411f, including fix 4's explicit positive-fixture
binding. New runtime and red/candidate results remain required. No public RPC,
port signature, driver or command/tool permission policy changes.

| Review item | Concrete correction and regression | Consumers that adapt |
| --- | --- | --- |
| Fable P2 / Gemini P2 #1: integrate-owned file inputs | Register all eleven owned methods with shared production semantic validators. TestOwnedFileInputs supplies valid and invalid data to every owned validator. TestFileInputHook adds exact append/decision errors and an actual bounded file append through Run's shared invokeFile path to its supplied socket. TestFileInputCatalog audits every owner's catalog entry against registered validators or explicit unavailable common file forms; an integrate method cannot use the unavailable exception. Controls delete append/decision registrations and bypass semantic checking. | records/service, common CLI and all feature CLI registration owners, dashboard/socket callers, INTEGRATE-RECORDS/controller |
| Gemini P2 #1: fail-closed and registration boundaries | TestFileInputHook invokes an unregistered guidance method before registration, requiring the exact owning not_implemented, exit 69 and empty stdout. Nil, foreign-owner and duplicate registration cells require invalid_request and their exact diagnostic. Separate controls bypass each gate. No binding or transport failure counts as a semantic refusal. | every feature adapter, common CLI, installed CLI fixtures |
| Fable P3: internal public reply | Move the existing late internal-Reply refusal into the internal branch alongside Deferred. The base already refused internal replies at its final reply check; this is an explicit early contract check, not a newly demonstrated accepted reply. TestInternalWriteAuthority / internal_reply and its omitted-guard control pin the prohibition. | service/store, all internal transaction producers, publisher completion |
| Fable P3: completion approval use | Remove Approval from org_publish, upgrade_apply and migration_apply guard sets. TestCompletionApprovalGuard keeps Cancellation valid and rejects Approval on all three; three controls restore those individual row defects. Original consumed authority is checked from the parent receipt without consuming it again. | approval/templates publisher, service/store/outbox, packaging/upgrade, migration |
| Fable P3: canonical deferred params | Compare exact envelope metadata, nil proof and canonical Params, then verify RequestDigest. Preserve RawRequest bytes. TestDeferredRequestEncoding accepts differently formatted equivalent input, rejects changed params/IDs/digest/proof and checks original-frame retention. Controls restore byte identity or remove both semantic/digest binding checks. | service dispatch/reservation/store, approval, publication/replay/recovery fixtures |
| Gemini P2 #2: staging authority | Human-read always requires bound human authority; human-endpoint requires a human principal and endpoint generation. Session rows reject proof/ticket/approval use. UploadBegin and blob.commit object ACL owner/config match Scope. TestStagingAuthority preserves normal own lane uploads and verified human staging, and rejects both lane-only human methods, each consuming guard and foreign owner/config on begin and commit. Nine controls individually reopen those gates. | service/store uploads and authorization, identity, secrets, policy/guidance/judge, object ACL/rebuild |
| In-progress correction: service invariants | Retain every original in-place service preflight and decision generation check as well as the shared input calls. TestDecisionInputBoundary invokes DecisionsMutate directly with add carrying a record ID, add carrying a nonzero base, and changes with zero or maximum base; each requires invalid_request and no commit/proof use. Four controls bypass both the shared service call and the corresponding in-place guard to prove direct service enforcement independently of CLI behavior. | records/decisions service, every socket/dashboard client, store CAS/replay, reviewers |

At fix 5 the regression runner contained 70 Go controls, its verifier check and
two scanner controls: 73 total. Each requires a reached named red assertion and
the unchanged candidate's pass; setup/compile failures never count. These local
shape and socket fixtures do not replace installed authentication/publication
or E2E gates. The acceptance README names missing other-owner registrations as
an explicit prerequisite, including a health-stage refusal that never reaches
the service. No candidate runtime pass is inferred from the source changes.

### Draft.4 fix 8: public health before authentication

Measured on the installed service (serve E2E box lb-v2-serve-e2e-green5,
candidate 69a3c35): an unenrolled caller's `health` received "unavailable:
service connection failed". The transport rules say only health is public, while the
authentication order required Authenticate before any frame and closed the
connection on every failure, so no unauthenticated peer could reach health.
No public RPC, port signature, driver or permission policy changes.

| Item | Concrete correction and regression | Consumers that adapt |
| --- | --- | --- |
| Public health unreachable before enrollment | Transport reads one pinned first frame with a two-second deadline from accept and MaxFrameBytes before Authenticate. Valid health is the only reply before authentication, then close. Regression: an unenrolled native peer receives Health with the installed artifact digest; no-frame and slow-fragment peers lose the connection at the fixed deadline; invalid JSON, oversize, unknown fields and health proof/extras produce zero reply bytes; a non-health frame fails authentication without dispatch; a second health frame is never read. Linux tests per-fragment credentials and Darwin tests per-frame audit token plus writer lifetime, including passed-descriptor writers; unsupported native verification stays closed. | lb-v2-service transport and native identity/peer fixtures; transport implementation remains a consumer gate. |

### Draft.4 fix 9: launch-plan and outside-capture closure

This closes lifecycle CONTRACT-GAPS items 1 and the minimum start portion of 3.
It starts from `84b2f2e`. The counted lifecycle review confirms that these are
shared contract requests; its lane.check, parent-policy, review and worker-view
findings remain their owners' separate work. This is a coordinated unreleased
draft change to internal ports and matched helper DTOs. There is no new public
method, CLI command, agent driver, privileged path/argv RPC or second state
database. Types, validators and owner-named failing stubs are not a launched-lane
or installed-service acceptance result.

#### Reservation and the one internal planning operation

`LaunchPlanner.PlanLaunch(ctx, scope, LaunchPlanRequest{Lease})` is implemented
by lifecycle and invoked by the service outbox with the current claimed
`Effect.PlanLaunch`. Its payload is only a reservation ID. Scope stays the
authentic service execution scope; the durable original requester is carried
separately. IDs and copies of leases are selectors/comparison claims, never
bearer authority: the store and each worker independently read the current
claim, expiry, cancellation epoch and original operation before any effect.

The dispatcher retains the exact original frame in ReserveRequest as before.
After authorization/preflight, LaneStart/LaneAdopt/LaneResume/LaneTurn call
`StateStore.ReserveLaunch(ctx, scope, {OperationID})`. Continue supplies its
retained ContinuationID as well. This is one short transaction in the existing
service store, under the receipt, lane-name/life and cancellation locks:

1. Load the original operation by its config/principal/life/method/key/digest
   domain and its retained bytes. Reject a different operation, actor, request
   digest, stale base, changed budget or completed failure. Identical retries
   return the same reservation and pending Operation; they never execute a
   pending request again. ReserveLaunch is the atomic reservation-owner handoff,
   so the fresh handler does not await its own pending receipt.
2. For start/adopt, the **store** issues a fresh immutable child LifeID, run 1,
   life generation 1, reservation/launch/spec/grant-set IDs and the absent-life
   name claim. The request cannot supply any of those IDs. Derive parent/root/
   starter chain from the authenticated starter, enforce D9 and the parent grant
   ceiling, or verify the separate human root ticket's principal/config/endpoint,
   level/role/grant set/expiry. Consume TicketUse or the applicable original
   operation proof exactly once in this transaction. A later failed plan does
   not refund or manufacture that authority.
3. For resume/turn, retain the existing life and reserve its next run, expected
   life generation plus one and PreviousLaunchID under CAS. Require uncleaned,
   quiescent ended prior containment, unchanged private session/workspace,
   current policy/grants and budget/counters. Cancel the old continuation intent
   with the existing epoch guard. Continue additionally requires the current
   durable continuation claim, exact swap/eligibility/slot fences and the same
   logical turn; it cannot reset counters, budgets or select a paid fallback.
   Retain a genuine service/scheduler/watchdog causal requester where applicable;
   do not substitute a human, parent lane or carried mail sender.
4. Persist `LaunchPlanRecord{phase:reserved,generation:1}`, exact original input
   as a private service-origin `launch_request` object, the pending Operation
   reply and exactly one PlanLaunch outbox intent atomically. Its target is the
   reserved run. Preserve §4's starter semantics: roots have sequence 0 and an
   empty chain; a child references its direct parent's authentic created/adopted
   event, with chain ordered root to direct parent and excluding itself.
   Retained lives keep their original starter edge.
   No fabricated complete Lane/LaunchEvent or live endpoint is needed here.

The original public Operation reply is retained byte-for-byte. Its pending
status acknowledges intent; operation.get later reports actual completion.
The store's private reservation insert is available only through ReserveLaunch,
not public StateWrites. A generic transaction cannot create/reissue a reserved
child. An issued name/life remains claimed until its failure/quiescence/owned
collection is recorded; a lost reply never frees it for another launch.

`GrantValidateRequest` remains the unchanged public preview without child IDs.
Its Effective result is not an issued launch grant set; root grant templates
also do not acquire a caller-invented life. Internal
`GrantResolver.Resolve(ctx, scope, GrantResolveRequest{ReservationID})` loads the
reservation and original request/ticket itself. It issues or reads the exact
reserved GrantSetID and binds `GrantSet.LifeID == reservation.Target.LifeID`,
ParentLifeID and policy generation to that reservation. It validates the actual
starter's current subset, revocation/expiry and sealed delegation lease before
returning the resolved set. The planner, under its original effect claim, commits
that reserved set and grants.issued with grant CAS/cancellation before source
resolution; Resolve itself does not claim an effect or perform external work.
An identical retry reads that same issued set. No preview or caller-supplied
GrantSet substitutes for this.
For a retained life, Revalidate narrows/checks its prior grants; ReserveLaunch
retains that life-owned grant-set ID and Resolve must not mint replacement scope.

#### Trusted order before a spec exists

The planner executes the following order. Every external stage has its durable
effect IDs and inputs recorded before invocation; actual helper/worker receipts
are retained through CompleteEffect. A claim loss resumes those same stages.
No global lifecycle/store lock is held while waiting for a worker or helper.

| Stage | Trusted input and result; responsible functions |
| --- | --- |
| 1. Resolve grants | `GrantResolver.Resolve(GrantResolveRequest)` above, or Revalidate for a retained life. Read the actual receipt and target policy generation without relabelling the requester or using an own-life briefing query for another life. |
| 2. Select sources | `admin.ResolveLaunchSources(LaunchSourceRequest{ReservationID,GrantSetID})` reads the protected installed LaunchEnrollment, original logical ProjectID and approved role/driver/profile policy. Return LaunchSources with ProjectLaunchSource and LaunchRuntime. Persist these exact LaunchInputs at phase sourced before allocation. |
| 3. Allocate ownership | Existing Helper.Allocate uses ReservationID, a distinct helper_allocate cause, reserved life/run, installed backend, bounded budget and the selected enrolled runtime manifest. It creates/reconciles the life UID and run containment, endpoint generation and protected storage registry. Save its actual HelperLease in the effect outcome; Allocate executes no agent. |
| 4. Prepare data/home | `DataWorker.MaterializeLaunch({ReservationID,GrantSetID,LeaseID})` reloads the sourced record and helper allocation, calls `admin.ResolveLaunchStorage` for the journal's LaunchStorage, runs the fixed confined data/Git job and returns LaunchData. It imports the exact enrolled/granted object and base into a private repository, creates service-derived `lane/<LifeID>` branch and private home/history, and returns actual materialization identities/snapshot and PrivateHomeBinding. |
| 5. Build runner inputs | Credentials.Acquire/Inject use the reserved LifeRef and the exact resolved profile/task-secret grants. Runner.Start/Resume/Turn receives only the enrolled Executable, prepared private home/session/cwd, selected slot and committed prompt. The pinned D8 adapter produces RunnerPlan; it does not execute it. Guidance/prompt selection and mail acknowledgement keep their existing turn claims and exact input bytes. |
| 6. Bind capture | admin.RegisterCapture creates/attests the fixed outside supervisor and one-use pipes, or the planner records the narrowly defined explicit refused binding below. This disposition is mandatory before release. |
| 7. Seal plan | ValidateLaunchPlan checks all cross-object pins. Commit LaunchPlanRecord phase planned and launch.planned under the current claim, CompareLaunchPlan and cancellation guard. This complete object precedes LaunchSpec and PreparedSpecHandoff. |
| 8. Retain spec | Build the complete agent LaunchSpec from that plan, including required PlanID/Capture. ValidateAgentLaunchSpec, serialize JCS, retain its exact bytes as private service-origin launch_spec, and commit phase spec_retained with the complete PreparedSpecHandoff. Only now call Launcher.Prepare. |

`LaunchEnrollment` is schema `laneboss.launch-enrollment.v2`, a protected
administrator-installed metadata object in the existing object/enrollment
universe. `assembly.Installation.launch_enrollment` is its optional manifest
reference, passed with RuntimeManifest to admin. Omitting it preserves public
health/diagnostics, but ResolveLaunchSources refuses launch with an owning
prerequisite result; it cannot infer paths or synthesize a catalog. Its project
entries map logical ProjectID to an immutable granted ObjectManifest, exact
40/64-hex base and history scope `tree|reachable`. Runtime entries uniquely map
the approved D8 driver to an enrolled executable and the **installed** runtime
manifest. Optional Supervisor is the fixed installed capture job's executable.
Admin verifies object bytes/hash/schema/config, protected enrollment origin and
generation, plus RuntimeManifest's root-relative object IDs/roles/pins. An
uploaded manifest with the same class label is not enrollment. Initial
administrator installation and already approved D6 resource publication retain
their existing authority; this adds no lane-controlled enrollment operation.

Executable enrollment includes its Linux loader closure. The administrator's
runtime dependency collector reads ELF64 little-endian program headers with the
Python standard library, without requiring binutils. It supports aarch64 and
x86_64, reads PT_INTERP and PT_DYNAMIC, and maps DT_STRTAB through file-backed
PT_LOAD extents for DT_NEEDED and SONAME. Header counts, dynamic records and
string lengths are bounded; unsupported formats, ambiguous tables, out-of-file
extents and unterminated strings are refused. The collector resolves the
transitive names with that native loader in a clean environment, and stages each
resolved regular file as a separate RuntimeObject with its exact ABI path,
SHA-256, byte count and mode. Script shebang interpreters are enrolled recursively;
an `env` launcher also enrolls its fixed program. A pinned `runtime-links.json`
artifact records the interpreter and dependency edges. The installed manifest
and the descriptor-pinned gate recheck those bytes before any native spawn.
Interpreters are 0555 and libraries are 0444, each bound read-only at its recorded
path. No host library directory is mounted, and launch performs
no fallback discovery. Changed pins stop preparation, and an unlisted host
library remains outside the lane view. The collector refuses unresolved names,
ambiguous shebangs and paths outside the supported system ABI roots.

The measured Claude runtime additionally enrolls individual successful file
paths from the retained 2.1.296 observation: the seven measured shared libraries,
the exact host-policy/time/OS files, loader cache, CA bundle and measured locale
files. Each source candidate is classified using the unchanged protected-source
check before its contents are opened. Accepted regular files are copied with a
SHA-256 pin; absent or unprotected files stay absent, with their classification
and reason retained. The collector never enumerates a host directory. Trust is
supplied by the one measured `/etc/ssl/certs/ca-certificates.crt` bundle, which
must itself be a protected regular file, not a symlink. The measured
`/etc/ssl/cert.pem` name receives an explicit alias of that same pinned bundle;
no host file at the alias is opened. Individual certificate names are recorded
as omitted and never enrolled. The collector's 100-object closure bound and the
manifest's 128-object bound remain unchanged. At most eight explicit aliases
are supported under the SSL certificate paths. Every
alias is a separate read-only FD bind of those pinned bytes; directories,
escapes, duplicates and non-certificate aliases are refused. Non-SSL etc paths
are named individually by the gate, with no general etc prefix.

Host resolv.conf is never enrolled or projected. A network grant retains the
existing sealed private resolver and its firewall policy; only that resolver
owns the active resolv.conf. The gate
already mounts its PID namespace's proc read-only and the lane's allocated
private home read-write. It does not mount host sys; these observations add no
sysfs or host-home projection.

The per-file classification is explicit: resolv.conf is supplied by controlled
egress; hosts, nsswitch.conf, gai.conf, host.conf, ld.so.cache, localtime,
machine-id and os-release are pinned only when their resolved regular file and
parents pass the source check. Otherwise libc uses its resolver/address-policy
defaults, the loader searches its fixed ABI paths, time display defaults to UTC,
or optional host-identification metadata is unavailable. The bundle and its
measured alias supply the same pinned trust store. A missing or rejected bundle
is an enrollment failure; TLS certificate
verification is never disabled. The installed DNS/TLS root test uses production
egress's real public resolution, private namespace, firewall and sealed resolver,
with a negative control that removes the CA pins and must fail verification.

Project selection additionally requires exactly one matching effective DataGrant
for `/work/main`, source ID/hash and history scope. The data worker verifies the
base against imported Git objects within reachable history, or the exact
ObjectManifest snapshot hash for tree-only input, never by invoking
repo-selected hooks/filters/config as the service. A file/subtree stays a tree
snapshot and cannot disclose other refs. Main logical cwd is `/work/main`;
PrivateHomeBinding.RootID resolves a helper-owned opened storage identity and
life/allocation generation, not a host path or arbitrary blob. Helper/worker
independently reject aliases, escapes and overlapping work/home ownership.
ResolveLaunchStorage requires no spec: Allocate has already created/journaled
the workspace/home/history identities under that reserved life. It returns only
LaunchStorage IDs and PrivateHomeBinding. The fixed worker bootstrap projects
their verified destinations into its job namespace; it supplies no generic
descriptor transfer or service-side opening of a client path. The worker retains
that registry receipt in its stage input/outcome and must return the same
Workspace.ID/Home binding. Repeated resolution opens/rechecks the same owned
objects. It never reallocates a home after a missing journal entry.
Materialization alone remains a data receipt; LaunchData is the missing wrapper
that binds it to the reservation, source, lease, Workspace and private home.
RunnerPlan.CWD and Session.LogicalCWD identify that logical workspace. The helper
resolves its actual opened identity for chdir; native Darwin maps it to the
life-owned native directory, never opens a logical label as a host path.
Session.VendorVersion is the actual pinned vendor version, not necessarily the
Claudock wrapper's Executable.Version. The adapter verifies the separate wrapper
and vendor runtime pins/compatibility from protected RuntimeManifest objects.
LaunchRuntime.SessionExecutable retains the exact history-owning executable
ID, digest and version. With separate Claudock/Claude objects it must select
the pinned Claude object, never the wrapper or a fixture descriptor. The
planner validates this enrollment before credential acquisition for every
Claudock mode; missing, ambiguous or mismatched metadata returns prerequisite.
For a fresh conversation it derives a stable UUID from the service-owned
logical session and that enrolled pin, then retains both UUID and exact vendor
version in input-runner. The runner must preserve the complete session. Resume,
turn and adoption retain their existing UUID and require the enrolled version
to match; they cannot replace a conversation to accommodate an upgrade.

On resume/turn/Continue, source selection reads PreviousLaunchID's committed
LaunchBinding and the existing private workspace/home/history/session. It
revalidates their actual registry identities and grants, snapshots current
private workspace bytes and creates a fresh run boundary around those same
objects. It must not recopy an initial project over edits, create a fresh home,
select a new history or re-enroll another runtime on a retry. An incompatible
installed upgrade requires an explicit supported migration, otherwise refusal.
Credential slots remain transient, outside history and source archives.

The materialization job does not recursively plan an agent to obtain its own
workspace. The existing fixed-worker framework uses its already enrolled
WorkerPlan/runtime and helper-created private job scratch. Its narrow job
capability projects only the source grant and allocated destination identities;
the worker cannot expose the service store, human home or arbitrary paths.
It is a worker principal, never a third D8 agent driver.

RuntimeResolver.ResolveRuntime(PreparedSpecHandoff) remains **post-spec**: it
checks the retained plan's existing selection/materialization and installed
root-relative runtime/endpoint/network objects, rather than choosing a runtime
or allocating a home after seeing an incomplete spec. All existing bwrap,
Landlock, namespace, peer, current-grant and helper gates remain mandatory.
These enrolled launch targets constrain D8 agent/fixed-worker setup only;
ordinary coding tools, new build outputs and user commands remain R48 blacklist
only. No command/tool allowlist is introduced.

#### Retention, identity commit and restart

LaunchPlanRecord has monotone revision CAS and closed phases reserved → sourced
→ planned → spec_retained → bound → opened, or a recorded failed phase. The store
also retains the actual original receipt/frame, immutable plan/input/spec object
bytes and all allocation / materialization / credential / capture / helper effect
receipts. New reservations cannot be submitted through a generic transaction.
Plan updates require the exact causal service actor/requester/request/operation,
CompareLaunchPlan generation increment and the original cancellation epoch.
Until a new life has a Lane projection, that cancellation guard resolves the
store's reserved-life fence; it cannot infer an epoch from an absent Lane.
The new launch_plan write row permits only LaunchPlans, Grants, Objects and
WorkerLeases; it cannot write policy, decisions, enrollments or identity permits.
Helper_prepare/open/abort rows additionally permit LaunchPlans only for their
bound/opened/failed transition. Generic effect_complete cannot launder plan
writes: completion applies the original kind and current stage claim.

After a real nonexecuting Prepare, the service atomically persists the exact
LaunchRecord, PreparedLaunch, endpoint, **LaunchRecovery** and phase bound with
identity.bound. The same helper_prepare transaction also writes the complete
ready Lane and TurnSnapshot; a new life emits its real lane.created/adopted
LaunchEvent there, while a retained life advances its reserved run under life
CAS. The identity consumer can therefore read the actual child projection
before issuing a permit. A reservation is never that ready projection.
LaunchRecovery includes PlanID, OriginalRequest, complete
PreparedSpecHandoff, PrivateHomeBinding and CaptureBinding. The store stamps the
actual IdentityCommit event/sequence and JCS LaunchRecord digest in that same
commit. `StateStore.LaunchBinding(LaunchID)` returns this whole retained tuple.
ValidateLaunchBindingPlan checks its plan / spec / home / request / capture / lease / record
pins; identity.BindLaunch additionally reads that exact tuple and committed
event back, checks current grants / policy / epoch / endpoint / containment and returns
only the matching permit. Missing recovery data cannot mean a legacy new launch.

Linux ControlSource is now the shared `api.LaunchControlSource`; service.Server
supplies the installed dependency through assembly. Handoff/Original read the
stored full spec and its exact committed bytes, not a remarshal represented as
the original object. PrepareIntent / Open / Observe / Stop / Abort / Release resolve the
current real stage claim, distinct helper cause and original requester;
Binding reads StateStore.LaunchBinding. RecordRelease/RecordAbort complete only
the original effect with the helper's actual receipt. Probe uses independent
installed-helper evidence and cannot recurse through Doctor/the launcher probe.
It is not a context.Value label, mutable launch-ID authentication map or second
helper wire protocol. Until implemented these methods return lb-v2-service's
typed not_implemented; assembly wiring alone is not permission to call a helper.

| Restart point | Required recovery |
| --- | --- |
| Only reserved/sourced | Reload the original input and pinned sourced data, recheck authority, then claim the existing PlanLaunch/stage effect. Reuse the same child/run/IDs. No new request, runtime choice or child reservation. |
| Allocation or materialization uncertain | Reconcile the original helper lease and fixed worker job by their retained stage IDs/outcomes. Unknown resource identity or prior boot refuses; do not allocate replacements or overwrite private data. |
| Spec retained, no identity commit | Reload the exact spec/home/request/plan. Reconcile only its original prepared gate. A known nonexecuting gate may complete the original guarded identity transaction or be aborted; missing/mismatched retained data refuses. No speculative OpenGate. |
| Identity committed, gate uncertain | Reload LaunchBinding and validate all its recovery pins, then ReconcileGate on that same lease/launch/prepared/operation. A known prepared gate may consume its original matching permit once after fresh authorization; an already consumed permit reconciles to the original process. Unknown state never opens another gate. |
| Process already running/ended | Observe the actual retained process and capture job; reconcile original effect/reply and actual exit/survivors. Do not relaunch because a reply, connection, service process or capture producer disappeared. |

Revocation, changed policy, dirty/missing private history, a stale claim or a
lost/unknown process prevents release and records the owning refusal. Cleanup
uses existing stop/abort/helper-measured release and verified archive rules;
no speculative UID reuse, force removal or fabricated successful end is added.

#### Minimum outside capture required for start

RegisterCapture takes a launch_plan Cause and reservation/helper/worker lease IDs
over the authenticated helper channel. The service first commits a WorkerLease
of fixed kind `capture_supervisor`, bound to that run, causal operation/effect,
runtime manifest, narrow input and allocation generation/expiry. The helper
verifies it from protected state, the installed supervisor executable and the
actual producer kernel lifetime. The supervisor runs outside the agent UID and
its writable grants, without arbitrary store, credential or shell authority.

The helper creates stdout/stderr pipes itself, names each PipeID once and
inherits only their read ends into the fixed supervisor job. Only the gated
agent receives their write ends as stdout/stderr. The optional vendor pipe
exists only for an actual pinned adapter's structured stream. Callers cannot
register an existing fd number, pass a descriptor over a lane RPC, provide a
spool path or select a producer executable. Unused ends close before exec;
another run never acquires the reads. The binding attests config/reservation/
life/run/launch/helper lease, original operation/request/requester, worker
lease/effect, producer principal/kernel generation/boot, executable pin and
unique stream/pipe IDs. No lane label or later transcript is that attestation.

Before OpenGate, the plan, spec and LaunchBinding retain one explicit status:

- `registered`: exact helper-attested producer and stdout/stderr bindings;
  capture.bound is committed first. Registration alone does not claim EOF,
  complete tool coverage or successful vendor/session interpretation.
- `refused`: a committed capture.refused with the owning typed
  not_implemented/unavailable/unsupported error, original operation ID and
  incomplete-evidence status. There is no producer/stream/primary record claim.
  This disposition requires current EffectivePolicy.AllowCaptureRefusal=true
  and the exact consumed D6 CaptureRefusalApprovalID, pinned at the reservation's
  policy generation and retained as CaptureBinding.RefusalPolicy. Missing policy
  defaults to false and stops launch. Only that explicit exception permits the
  isolated agent to run; the helper uses a nonblocking discard for stdout/stderr
  recorded by this refusal. No bytes are advertised as captured. Review/accept
  and capture-dependent session/limit continuation remain blocked. Missing
  capture is invalid. Authentication, integrity, unknown ownership or guard
  failures cannot be converted into this fallback. Any partial capture job
  must be independently quiescent/collected before using refused; otherwise
  the launch stops with the original failure. Remove the exception through D6
  once the installed capture supervisor supports the enrolled runtime; never
  advertise full capture, review acceptance or continuation while it is active.

For registered capture the supervisor durably spools bounded exact ranges under
its own lease before upload. It never acknowledges a pipe range until the
service has retained its bytes and AppendCapture committed an acknowledgement.
`StateStore.AppendCapture(ctx, scope, CaptureAppendRequest)` accepts only that
authenticated worker principal/lease and capture_append intent, binding/stream,
original operation/request/requester, target and current capture revision. It
checks immutable object class/hash/length/ACL/source operation, contiguous
stream offset and CAS. It derives CaptureRecord.ID/BindingID, primary provenance
and the canonical event envelope; callers submit neither primary nor records.
The installed supervisor reaches service.Server.CaptureState/AppendCapture
through the fixed private outside-job channel authenticated as its worker
endpoint/lease. The server derives Scope from that connection and attestation,
then calls the store; a body cannot supply Scope or an InternalIntent principal.
This typed ingress adds no public Methods entry, generic internal-event append,
passed descriptor or caller-selected command.
An identical binding/stream/offset/hash retry returns its original receipt,
before a stale-revision rejection; different bytes at that offset conflict.
EOF has no Data and records capture.closed only after the actual pipe is closed
and its spool is acknowledged. Nil/unknown counts never prove a drain.
Append checks the current cancellation guard. After stop/revocation, only an
explicit retained drain claim for that original run and its unacknowledged spool
may continue under the new current epoch; an old producer/epoch cannot authorize
new live work. Original capture event operation/request/requester correlation
does not change to the stopping caller.

After service restart, CaptureState returns the exact binding, per-stream
committed next offsets/EOF, revision and sequence. ReconcileCapture verifies the
same live kernel producer and protected spool/pipe lease against the helper
journal. Replay only unacknowledged ranges, retaining the original requester
and operation; never re-register another pipe as continuation of that stream.
After producer loss, prior boot, full spool or an unreadable/unhashable range,
pause/stop the producer/run as required and commit an explicit CaptureGap with
known range or unknown end. If the service is down, retain the failure/spool
marker and stop bounded work until it can be committed; do not discard while
claiming capture. Process end may record incomplete capture, never complete
coverage. Historical imports may omit BindingID; every new live CaptureRecord
and CaptureGap must carry it. launch.planned/capture.bound/refused are private
human/service metadata; the normal life/ancestor gap and dashboard projections
show missing capture without widening access to administrative objects.

**Named remaining request LP-CAPTURE-IO-1:** lifecycle/admin/identity/runners/
service must separately freeze the scoped stdin/resize/attach channel and
vendor-specific tool inventory/session/limit record schemas from real pinned
driver bytes. This closure defines registration, spool acknowledgement,
offset/EOF recovery and explicit gaps needed for start; it does not pretend a
text stream provides tool coverage. LaneInput/interactive attach and unsupported
vendor interpretation keep their owning typed unavailable barriers.

#### Consumer implementation map and gates

| Lane | Exact functions to implement/adapt |
| --- | --- |
| lb-v2-lifecycle | LaneStart / LaneAdopt / LaneResume / LaneTurn / Continue call ReserveLaunch and retain pending Operation; PlanLaunch orchestrates the stages, consumes current claims and seals plan/spec/recovery. LaneCheck/RunInternal preserve actual end/capture failures; input waits on LP-CAPTURE-IO-1. |
| lb-v2-grants / dataworker | Resolve uses GrantResolveRequest and the reserved child/grant IDs, Revalidate retains current ceilings; MaterializeLaunch reloads sourced inputs/helper lease and measures private workspace/home/materialization. Existing Materialize alone is not a launch plan. |
| lb-v2-admin | Load protected LaunchEnrollment/RuntimeManifest; ResolveLaunchSources, Allocate/ResolveLaunchStorage, RegisterCapture/ReconcileCapture, RegisterSpec/ResolveRuntime, Prepare / OpenGate / ReconcileGate / AbortGate / Release implement actual installed ownership and one-use gates. |
| lb-v2-identity | BindLaunch reads the complete LaunchBinding tuple and ValidateLaunchBindingPlan before the existing committed-identity permit checks; Authorize retains actual caller/worker and current endpoint identity. |
| lb-v2-linux (Darwin follows its own OS gate) | ControlSource aliases api.LaunchControlSource; Prepare checks ValidateAgentLaunchSpec against the retained plan, original bytes, enrolled runtime and home; Launch/OpenGate reconciles the same binding and permit. Observe/Stop/Abort/Collect keep actual helper receipts. |
| lb-v2-secrets | Acquire/Inject accept only the resolved reserved-life profile/task grants; eligibility and serialized refresh remain unchanged. Retained history/home never becomes a credential slot. Release/RevokeInjection require real quiescence. |
| lb-v2-claudock / lb-v2-codex | Start/Resume/Turn consume the plan's enrolled Executable/private Home/Session/Slot/Prompt and build only that pinned adapter's argv. SessionFromCapture/LimitFromCapture reject refused/unbound/supplementary evidence. |
| lb-v2-service / store | ReserveLaunch, LaunchPlan, ClaimEffect/CompleteEffect/Transact, LaunchBinding, CaptureState/AppendCapture and service LaunchControlSource methods implement one-store transactional fences, retained bytes and restart reconciliation. BindRuntime must require LaunchPlanner and the actual recovery/capture jobs before advertising launch readiness. |
| assembly | build/platformLauncher pass the installed admin source/capture resolvers, server's LaunchControlSource and lifecycle LaunchPlanner. Missing implementation remains an owner-named error; no synthesized permissive adapter. |

The helper_prepare/open/abort field rows gain LaunchPlans; helper_prepare also
gains Lanes/Turns and lane.created/adopted solely for the atomic ready binding
above. All other fields/events/guards stay as listed. Public start/adopt/resume/turn add
PlanLaunch to their effect catalog, but gain no LaunchPlans write authority.
ReserveLaunch is the private atomic insert described above, not a route around
proof/ticket/CAS checks. New starts initially enqueue PlanLaunch, never a second
concurrent full Launch effect. Other existing staged consumers may retain their
documented helper/worker/launch effects under the same closed causal chain.
EffectOutcome.LaunchPlan is only the current plan effect's measured completed
plan; deferred D6 publication explicitly refuses that competing outcome.

The shape regressions are TestLaunchReservationShape, TestLaunchEnrollmentShape,
TestLaunchInputReservation, TestLaunchPlanShape, TestAgentSpecPlanBinding, TestLaunchRecoveryBinding,
TestLaunchPlanPhases, TestLaunchSelectorShapes, TestLaunchPlanWriteAuthority,
TestLaunchBoundTransaction, TestCaptureBindingShape, TestCaptureAppendCorrelation and TestLaunchPlanEffectUnion.
Their valid fixtures and negative cells check actual inputs/correlations; they
do not count a stub's not_implemented as an implemented launch. The fix-9 controls
are activated by fix 10; their consumer/installed acceptance rows are listed in
[LAUNCH-PLAN-CONTROLS.md](../.. / e2e / v2 / cases / integrate / LAUNCH-PLAN-CONTROLS.md).
Run the new reds and candidate tests on the disposable Linux machine; static
vet/formatting is not runtime red/green or OS-LINUX/LIFECYCLE-TREE/serve evidence.

#### Exact new retained object maps

The JSON-tagged objects below are internal retained/helper data, not added public
Params unions. Go-only LaunchPlanRequest is `{Lease: EffectLease}`; internal
StateWrites adds `LaunchPlans []LaunchPlanRecord`, CompareKind adds launch_plan,
Effect adds `PlanLaunch *LaunchPlanEffect`, EffectOutcome adds
`LaunchPlan *LaunchPlan`, and LaunchBindingRequest adds `Recovery *LaunchRecovery`
(required for agents). RuntimeServices adds LaunchPlanner. GrantResolver.Resolve
uses GrantResolveRequest while public GrantsValidate keeps GrantValidateRequest.

| Object | Complete field map |
| --- | --- |
| LaunchReservationRequest | `{operation_id: ID, continuation_id?: ID, guards?: []TransactionGuard, loop?: LoopTurnSelector}` |
| LaunchAuthority | `{kind: string, id: ID}`; ticket, proof or starter references consumed authority; scheduler references the installed CapabilityID. |
| LaunchReservation | `{id: ID, config: string, mode: string, level: integer, role: string, driver: Driver, authority: LaunchAuthority, target: LifeRef, launch_id: ID, spec_id: ID, grant_set_id: ID, generation: integer, base_generation: integer, cancellation_epoch: integer, policy_generation: integer, parent_life_id?: ID, root_life_id: ID, starter_chain: []ID, starter_event_seq: integer, operation_id: ID, request_id: ID, request_sha256: Digest, requested_by: Actor, original_request: BlobRef, previous_launch_id?: ID, loop?: LoopTurnCause}` |
| LoopTurnSelector | `{target: LifeRef, setting_event_id: ID, setting_seq: integer, setting_operation_id: ID, end_event_id: ID, end_seq: integer, expected_generation: integer, cancellation_epoch: integer, previous_launch_id: ID}` |
| LoopTurnCause | `{schema: string, scheduler: InstalledScheduler, selector: LoopTurnSelector, configured_by: Actor, setting: LoopRequest, end: RunEndEvent, grant_generation: integer, previous_session: Session, previous_home: PrivateHomeBinding, budget_remaining: Budget, due_at: Timestamp, reserved_at: Timestamp, reservation_id: ID, operation_id: ID, request_id: ID, launch_id: ID, grant_set_id: ID, logical_turn_id: ID, previous_logical_turn_id: ID, plan_effect_id: ID}` |
| InstalledScheduler | `{config: string, actor: Actor, capability_id: ID, capability_generation: integer, installation_generation: integer, boot_id: string, policy_generation: integer, expires_at: Timestamp}` |
| InstalledAttestationPolicy | `{schema: string, config: string, installation_generation: integer, roots_der: []string, allowed_aaguids?: []string}`; DER elements use standard base64. |
| PlanCleanup | Go-only private outbox object; the complete field map is [api/plan_cleanup.go](../../internal/v2/api/plan_cleanup.go). It has no public JSON DTO. |
| GrantResolveRequest | `{reservation_id: ID}` |
| LaunchPlanEffect | `{reservation_id: ID}` |
| LaunchSourceRequest | `{reservation_id: ID, grant_set_id: ID}` |
| LaunchEnrollment | `{schema: string, config: string, generation: integer, projects: []ProjectEnrollment, runtimes: []LaunchRuntime, supervisor?: Executable}` |
| ProjectEnrollment | `{id: ID, generation: integer, project_id: ID, object: BlobRef, base: string, history_scope: string}` |
| ProjectLaunchSource | `{enrollment_id: ID, generation: integer, project_id: ID, grant_id: ID, object: BlobRef, base: string, history_scope: string}` |
| LaunchRuntime | `{enrollment_id: ID, generation: integer, backend: string, driver: Driver, executable: Executable, manifest: BlobRef, session_executable?: Executable}` |
| LaunchSources | `{reservation_id: ID, project: ProjectLaunchSource, runtime: LaunchRuntime}` |
| LaunchDataRequest | `{reservation_id: ID, grant_set_id: ID, lease_id: ID}` |
| PrivateHomeBinding | `{life_id: ID, root_id: ID, generation: integer, home: PrivateHome}` |
| LaunchStorage | `{reservation_id: ID, target: LifeRef, lease_id: ID, workspace_id: ID, home: PrivateHomeBinding}` |
| LaunchData | `{reservation_id: ID, target: LifeRef, lease_id: ID, source: ProjectLaunchSource, workspace: Workspace, home: PrivateHomeBinding, materialization: Materialization}` |
| LaunchInputs | `{grants: GrantSet, sources: LaunchSources}` |
| LaunchPlan | `{reservation: LaunchReservation, inputs: LaunchInputs, lease: HelperLease, data: LaunchData, runner: RunnerPlan, injection: Injection, budget: Budget, capture: CaptureBinding, capture_policy?: EffectivePolicy}`; capture_policy is mandatory for a refused disposition. |
| LaunchPlanRecord | `{reservation: LaunchReservation, generation: integer, phase: string, inputs?: LaunchInputs, plan?: LaunchPlan, handoff?: PreparedSpecHandoff, error?: Error, data_stage_id?: ID}` |
| LaunchRecovery | `{plan_id: ID, original_request: BlobRef, handoff: PreparedSpecHandoff, home: PrivateHomeBinding, capture: CaptureBinding}` |
| CaptureStreamBinding | `{id: ID, stream: string, pipe_id: ID}` |
| CaptureRefusalPolicy | `{allowed: boolean, policy_generation: integer, approval_id: ID}`; comparison metadata, never authority by itself. |
| CaptureBinding | `{id: ID, config: string, reservation_id: ID, target: LifeRef, launch_id: ID, helper_lease_id: ID, operation_id: ID, request_id: ID, requested_by: Actor, generation: integer, status: string, worker_lease_id?: ID, effect_id?: ID, producer_id?: ID, producer_generation?: string, boot_id?: string, supervisor?: Executable, streams: []CaptureStreamBinding, refusal?: Error, refusal_policy?: CaptureRefusalPolicy}` |
| CaptureRegistrationRequest | `{cause: InternalIntent, reservation_id: ID, helper_lease_id: ID, worker_lease_id: ID}` |
| CapturePosition | `{stream_id: ID, next_offset: integer, eof: boolean}` |
| CaptureState | `{binding: CaptureBinding, generation: integer, positions: []CapturePosition, last_seq: integer}` |
| CaptureAppendRequest | `{intent: InternalIntent, binding_id: ID, expected_generation: integer, stream_id: ID, offset: integer, data?: BlobRef, eof: boolean}` |
| CaptureAppendReceipt | `{binding_id: ID, record_id: ID, stream_id: ID, offset: integer, next_offset: integer, generation: integer, last_seq: integer, eof: boolean, replayed: boolean}` |

### Draft.4 fix 10: authority gates and consumer handoffs

This additive correction starts from ad7cfab. The supervisor's reported green
fix-9 Linux baseline is input evidence, not a measurement of this candidate.
Existing public methods and launch-plan port signatures stay fixed. New fields
and private ports below must be consumed by one matched contract generation;
old strict decoders are not mixed into a live deployment.

#### Reservation authority and prepared bindings

ReserveLaunch calls ValidateLaunchReservationRequest before any reservation
write. Guards have the same closed one-of shape as TransactionGuard. A human
start/adopt requires exactly one TicketUse, bound to the authenticated principal,
config, endpoint generation and original request's ticket/level/role, with a
nonempty ticket-authorized root GrantSetID. The store checks that actual set.
TicketUse.Target is empty at submission because the store has not issued the
child yet; under the same reservation lock the store assigns the issued target,
verifies actual grant ceilings, expiry, ticket provenance and unused authority,
and consumes the ticket with the pending receipt/reservation/PlanLaunch commit.
A lane cannot carry any frame ProofRef, ProofUse or TicketUse. Retained-life
resume/turn requires the exact cancellation fence; a human also supplies the
operation-bound ProofUse. Internal continuation accepts only its service-owned
continuation claim and cancellation guard, with no public method or human proof.
Original frame digest, current receipt, authenticated native identity and actual
proof/ticket verification remain store checks, not assertions from ID possession.

LaunchReservation.Authority retains ticket/proof/starter and the exact consumed
ticket/proof ID or authentic starter LaunchRecord ID. A continuation's starter
ID is PreviousLaunchID. The store derives Level, Role and Driver from that
retained request/current life after D9, role policy and parent grant-subset checks.
ValidateLaunchReservation rejects human root authority without a ticket and lane
authority with a human proof; ValidateLaunchBindingPlan compares the child's
Actor.Level/Role and ValidateLaunchPlan compares the driver with the reservation.
Recovery reuses these facts and never manufactures a new consumed authority.

ValidateTransactionShape now checks helper_prepare unconditionally, including
transactions with no LaunchPlans entries. Every new agent IdentityBindings row
has LaunchRecord.Kind=agent, Recovery and a matching valid bound plan in that
same transaction. Its complete identity binding is validated against that plan.
Every Lane row and lane.created/lane.adopted event also needs its matching bound
plan; life CAS, reservation CAS and cancellation guard remain mandatory. Worker
bindings use Kind=worker and Actor.Kind=worker under their separate fixed lease
path and cannot acquire agent Lane/event authority. Missing/legacy Kind is not
treated as a worker escape. Historical records may still decode without Kind;
they cannot become a newly authorized live binding by replaying an old shape.

Capture refusal now defaults to disabled. ValidateCapturePolicy compares the
binding's explicit allowed/generation/approval metadata with protected current
EffectivePolicy, and a refused LaunchPlan retains that policy snapshot. The
publisher/store must verify the actual consumed D6 approval, recheck policy and
revocation immediately before release, and stop on a stale or disabled exception.
Registered capture requires no refusal metadata. The previous refusal status,
blocked acceptance/continuation and collection rules still apply. The §14 emitter
table now names launch_plan; lane.check's public row also permits lane.state for
a measured natural completion, under the existing life CAS and current controls.

#### Closed review evidence

Coverage is the closed vocabulary complete, partial, unsupported, missing.
Complete means all required checks succeeded against the exact post-run snapshot,
all expected primary stream ranges reached EOF without gaps, tool-record coverage
is complete, and every refusal/suspected workaround has an authenticated resolution
through the pinned inventory sequence. Partial means some measured evidence is
available but this set is incomplete; unsupported identifies a missing verifier
capability; missing identifies absent required evidence. Failure/partial evidence
can be retained and displayed; only complete can authorize acceptance.

ReviewRequest continues to carry candidate object references. Lifecycle resolves
ReviewSubject from the actual ended life/run/LaunchID, lane generation, authentic
lane.ended event ID/sequence, drained CaptureBinding and vendor session, then pins
the workspace diff snapshot and an immutable read view through InventorySeq.
Required check names come from current protected project/policy, never the request.
ReviewVerifier.VerifyReview(ctx, scope, ReviewVerifyRequest) is a confined
dataworker port. Lifecycle issues its real WorkerLease through the existing
service-only object/worker path; no new public lane.review write authority is
added. The verifier uses the existing fixed test/export worker runtimes and
granted read-only sources. It measures the actual diff, actual test receipts
including exit/worker/operation and snapshot digest, exact capture ranges/EOF/gaps,
tool-record inventory and refusal resolutions. Objects are retained with their
class-specific trusted provenance and ACLs in the existing object store. A blob
class, requester label, executor success message or caller-authored receipt never
substitutes for those bytes or authentic measured jobs.

ValidateReviewEvidence compares the entire subject and check/run/end/snapshot
correlation and validates closed coverage/ranges. Lifecycle emits lane.reviewed
with a service-issued ReviewReceipt carrying this evidence. LaneMark resolves
the same current frozen subject and required checks, verifies the stored authentic
receipt, independent reviewer/control rights, actual object contents/provenance,
then calls ValidateReviewAcceptance before its atomic state/CAS commit. A changed
run/end/snapshot invalidates a prior review. Self-acceptance, failed/missing checks,
tool gaps, missing EOF and unresolved refusals refuse. Imported receipts without
Evidence remain historical data and do not authorize new live acceptance.

| Review JSON object | Complete field map |
| --- | --- |
| ReviewSubject | `{target: LifeRef, launch_id: ID, generation: integer, end_event_id: ID, end_seq: integer, snapshot: BlobRef, session_id: ID, inventory_seq: integer, capture_binding_id: ID, streams: []CaptureStreamBinding, refusal_ids: []ID}` |
| ReviewCheckFact | `{name: string, receipt: BlobRef, target: LifeRef, end_seq: integer, snapshot_sha256: Digest, exit_code: integer, worker_lease_id: ID, operation_id: ID}` |
| ReviewStreamFact | `{binding_id: ID, stream_id: ID, start_offset: integer, end_offset: integer, eof: boolean, gap_ids: []ID}` |
| ReviewInventory | `{manifest: BlobRef, through_seq: integer, streams: []ReviewStreamFact, tool_records: BlobRef, tool_coverage: string}` |
| ReviewResolution | `{refusal_id: ID, event_seq: integer, evidence: BlobRef}` |
| ReviewEvidence | `{schema: "laneboss.review.v2", subject: ReviewSubject, verifier_lease_id: ID, diff: BlobRef, checks: []ReviewCheckFact, inventory: ReviewInventory, resolutions: []ReviewResolution, coverage: string}` |

ReviewVerifyRequest is Go-only: Lease, Request, ExpectedGeneration, EndEventID,
EndSeq. Its lease/input binds the exact subject and original operation. The
verifier/store reads actual retained bytes and ends, not a public expected value.
The shared validators establish shape/correlation; they cannot authenticate a
native worker or prove a diff/test result without those consumer checks.

#### Fixed channel preparation and measured delivery

StateStore adds ChannelJobStore.PrepareChannelJob(ctx, scope,
ChannelPrepareRequest{OperationID, ChannelGrantID, DestinationID}). This is a
service-only preparation step under the already reserved exact pending public
mail/report receipt. It reloads original request bytes and current D7/channel
grants/enrollment, resolves the protected runtime and destination, assigns the
MailID/effect/WorkerLease/provider key once, and retains the exact input/payload
objects. Retries return that same staged job; changed intent conflicts. These
inert preparation records use the existing receipt/object/effect store. They do
not consume public ProofUse, enqueue a message, inject credentials, open a gate
or send. Final mail.send/report.submit atomically commits Mail, WorkerLease,
Channel effect and original reply under current grants, proof and cancellation
checks. A staged job without that commit cannot be claimed. Failed preparation
returns its owning typed error before queue publication; abandoned inert staging
is collected without pretending a delivery happened. No parallel delivery DB.

The enrolled ChannelRuntime pins Executable, actual RuntimeManifest and a closed
Reconcile capability: provider_key, receipt_id or unsupported. These are protected
installation facts. The service resolves them from current enrollment; channel
content never selects a path/executable/runtime. ChannelJob remains one enrolled
destination, one channel generation, one payload, one worker lease/effect and
one provider key. StateStore.ChannelJob reloads that same committed job under
the current effect claim. ConsumedBy, lease generation/expiry, current grants,
endpoint, enrollment and destination are checked at every claim/use/replay.
ChannelWorker rechecks that current claim through the retained effect/job, never
from a caller's copied ChannelJob. The worker's installed endpoint binding names
this exact WorkerLeaseID; its sealed input LeaseID must match. Stage handoff,
identity/permit and send/read-back receipts are retained under this existing
effect and worker lease for recovery; possession of these IDs is not authority.

ChannelWorker.PrepareChannel(ctx, scope, job) returns ChannelExecution with a
worker LaunchSpec handoff and committed worker identity. WorkerPlan uses the
existing laneboss.worker-plan.v2 schema and channel kind, with no RunnerPlan.
The executable is the enrolled installed laneboss worker; its exact argv is
`laneboss internal channel --binding /runtime/laneboss-worker.json --lease ID`.
The absolute binding path is fixed inside the job's protected runtime mapping,
never a caller-selected host path. The internal channel entry accepts exactly
that binding/lease grammar and verifies the worker endpoint's UID, launch,
target, lease and native process lifetime. It is not a public RPC. Input is the
lease's immutable channel_input object; the service mounts its protected binding
and source objects read-only. It registers exact JCS launch_spec bytes, prepares
the unopened gate, commits LaunchRecord.Kind=worker and the real IdentityCommit,
obtains the existing identity permit, then opens only that gate. A restart must
reconcile this retained handoff, never allocate a replacement send job blindly.

ChannelWorker.SendChannel performs credential injection and network work only
inside that authenticated confined worker. InjectWorker authorizes the enrolled
credential handles/versions for this lease and provides no send result. The
bounded laneboss.channel-input.v2 object seals all job/channel/destination/provider
IDs and exact payload/content/artifact references. channel_payload is the exact
bounded provider serialization derived from those authorized references. No
secret values enter retained input/result objects. Provider acknowledgement and
read-back bytes are retained as private channel_receipt objects with measured
observation time. Output uses laneboss.channel-result.v2 and binds the lease,
operation, effect, mail, destination, channel generation, provider key and payload
digest. Outcome is confirmed, uncertain, failed or unsupported. Only confirmed
with both actual acknowledgement and matching receipt/payload read-back can
produce delivered via ValidateChannelDelivery and EffectOutcome.Delivery.
Zero exit, a slot, successful injection or a worker's success text is insufficient.

ReadBackChannel reconciles the same retained execution/provider key or receipt ID,
without re-sending. Unsupported reconciliation returns the owning typed result;
an unknown network outcome stays uncertain, with no blind retry, new provider key
or duplicate message. Definitive failure and unsupported keep their actual error.
The outbox commits the measured per-destination outcome once under the original
claim; confirmed replay returns that receipt after current visibility checks.
The service UID never sends directly. Real provider behavior, credential
confinement and interruption/reconciliation need installed-service controls.

| Channel JSON object | Complete field map |
| --- | --- |
| ChannelSendInput | `{schema: "laneboss.channel-input.v2", lease_id: ID, mail_id: ID, channel_id: ID, channel_generation: integer, destination_id: ID, provider_idempotency_key: ID, payload: BlobRef, content: BlobRef, artifacts: []BlobRef}` |
| ChannelReadBack | `{remote_receipt_id: string, payload_sha256: Digest, response: BlobRef, observed_at: Timestamp}` |
| ChannelSendEvidence | `{schema: "laneboss.channel-result.v2", lease_id: ID, operation_id: ID, effect_id: ID, mail_id: ID, channel_id: ID, channel_generation: integer, destination_id: ID, provider_idempotency_key: ID, payload_sha256: Digest, outcome: string, remote_receipt_id?: string, response?: BlobRef, read_back?: ChannelReadBack, error?: Error}` |

Go-only ChannelRuntime has Executable, Manifest, Reconcile; EnrolledChannel adds
Runtime *ChannelRuntime. ChannelJob adds Runtime *ChannelRuntime and Payload
BlobRef. ChannelExecution has Job, Handoff, Binding. ChannelWorker adds
PrepareChannel, SendChannel, ReadBackChannel; messaging's Worker dependency
receives the dataworker from assembly. Missing ports return owner-named
not_implemented; no stub result is counted as preparation or delivery success.

#### One continuation operation

The ready/pending selection writer stamps Commit.Operation.ID into both
ContinuationIntent.OperationID and ProfileSwap.OperationID. Authored precommit
writes leave both empty. Retain the actual pending receipt even if selection
after waiting emits no new domain event; invent no extra watchdog.limit/swap.
One profile_continue operation spans selection, claim, persisted slot handoff,
watchdog.swapped, continued launch and reconciliation. Lifecycle.Continue returns
that operation. InternalIntent.ID remains a different intent identity; neither
its ID nor arbitrary cause text may replace the operation. Keep original actual
actor/requester/request cause throughout. Waiting journal updates may have their
own operations before pending selection. Cancellation has its own actual commit
operation, stamped into both fields with synchronized life/epoch fences.

ValidateContinuationOperation compares intent/swap/request/result identity.
Pending or claimed continuation intents may return an operation whose status
is pending or running; a completed intent returns an operation with succeeded.
Waiting/cancelled/unknown refuse launch/replay. Pending cannot claim completion.
Expired pending receipts do not acquire a slot or call Continue; claimed recovery
reconciles the same retained slot even after selection receipt expiry. Existing
claim, eligibility, cancellation and current grant checks remain required.
No Continue signature change is needed. The separate watchdog requests about a
human dashboard reader, cancellation cause argument and turn-status vocabulary
remain outside this correction; this rule does not claim to close those gates.

#### Regression and consumer adaptation

| Item | Regression/control and deciding failure | Consumers that adapt |
| --- | --- | --- |
| Reservation authority | TestReserveAuthority refuses missing/foreign ticket, lane proof/ticket and missing retained proof/epoch; TestReserveRecord refuses wrong retained authority and D9 level. | lifecycle supplies Guards; service/store calls the shared validator and consumes actual authority atomically; grants checks real parent subset; identity/recovery preserves Authority. |
| Bound plan required | TestLaunchBoundTransaction no_plan_bind/no_plan_lane removes LaunchPlans; life_cas removes only the bound life CAS. | lifecycle/store/identity provide Kind and same-transaction plan/identity/ready lane, including recovery; admin preserves the binding. |
| Child pins | TestReservedRolePins changes level/role with valid recomputed record hashes and changes only the reserved driver. | store derives pins, lifecycle and both driver adapters retain them, identity checks binding and ready lane agrees. |
| Health/emitter/capture | Expanded fix-8 installed transport row above; TestCaptureRefusalPolicy disables/mismatches D6 policy; capture producer/run/refused controls and closed PlanLaunch effect control. | service transport and native peers implement deadline/no-reply/per-frame checks; lifecycle/admin/grants/policy enforce current capture exception and actual D6 provenance. |
| Natural completion | TestCheckNaturalStateWrite requires lane.state in lane.check's catalog row. | lifecycle emits measured end/state under CAS; store/dashboard consume it without widening events. |
| Review evidence | TestReviewCoverageSchema and TestReviewAcceptance refuse changed run/end/snapshot/inventory, invented coverage, self-review, failed/missing checks, tool gaps, missing EOF and unresolved refusal. | lifecycle calls ReviewVerifier and shared acceptance checks; grants/dataworker measures jobs; store authenticates retained evidence; dashboard displays closed coverage. |
| Channel worker | TestChannelWorkerHandoff refuses changed sealed input/runtime/argv/binding; TestChannelMeasuredResult refuses missing/changed read-back, foreign operation, exit-only success and uncertain-as-delivered. | service/store prepares/commits/claims staged jobs; messaging calls Worker; grants/dataworker, admin/isolation/identity, secrets and assembly implement fixed worker/permit/credential path; E2E measures provider/recovery behavior. |
| Continuation operation | TestContinueOperation refuses swap/result ID changes, waiting launch and pending-as-succeeded. | watchdog/store stamps and retains selection operation; lifecycle returns/reconciles the same operation; dashboard/E2E correlate it. |

launch-plan-controls.json is now loaded by red-controls.py, including all 14
fix-9 controls and the new deciding controls. Parent grant ceiling/subset and
native health/worker provenance remain required installed-runtime rows in
LAUNCH-PLAN-CONTROLS.md. Static checks cannot demonstrate reached red. Linux
must execute each named assertion on its compiling mutant and the candidate,
then the unit/scanner/installed-service gates on these exact retained bytes.

### Draft.4 fix 11: consumer authority and worker handoffs

This additive correction starts from 3803f4d, including fix 10 and the landed
messaging/judge consumers. The eleven decisions below close the requested
representations and private ports. They do not claim implemented native
authentication, a running worker, verified human presence or installed serve
acceptance. Missing consumer implementations keep owner-named typed failures.
No new public RPC, agent driver, generic SQL read or caller-controlled resolver
is added. Install one matched schema/contract generation across all consumers.

#### 1. Durable read-session activity

IdentityStore now includes ReadSessionStore.RefreshReadSession(ctx, scope,
ReadSessionRefreshRequest{SessionID, ExpectedGeneration}). Identity calls it
after native/current read authorization on the already bound human connection.
The store atomically compares the session revision, prior idle and absolute
deadlines, exact connection / principal / credential / config / endpoint, current
enrollment and credential revocation, and live installed connection authority.
Its own clock sets IdleExpiresAt=min(now+5 minutes, unchanged absolute expiry),
advancing Generation once. An expired/revoked session is never revived. This is
a private refresh of an existing session, not another human.session, public
write row or proof consumption. Reads and staging/previews otherwise keep their
existing authority and receipt-first rules.

ReadAuthority adds Generation and SimulatedPresence. The transport implements
the named ReadAuthorityRefresher capability in addition to ConnectionContext;
absence is an explicit owning failure. RefreshReadAuthority(ctx,
ReadAuthorityUpdate{Before, After}) compares its current cached authority with
Before, then permits only the next generation and the committed idle deadline
for that same identity and absolute expiry. ReadAuthorityFromSession supplies
the exact metadata projection; it grants nothing by itself. BindReadAuthority
remains one-use. Requests/refreshes on one connection are serialized; a stale
CAS reloads/reconciles the same session, never binds a replacement. After the
store update, a failed/closed transport refresh closes that connection. The
next Scope snapshot is obtained from the refreshed connection. Store callbacks
into transport while holding its writer lock remain forbidden.

#### 2. Declared software authenticator and presence provenance

The shared identifiers match the serve owner's declared fixture:

| Constant | Value |
| --- | --- |
| SoftwareAuthenticatorAAGUID | `6c626f73-732d-4565-9273-6f6674617574` |
| SoftwareAuthenticatorAttestationMarker | `laneboss-e2e-software-auth-v1` |
| SoftwareAuthenticatorBuildTag | `laneboss_e2e_authenticator` |
| SoftwareAuthenticatorCredentialID | `laneboss-e2e-software-auth` |
| SoftwareAuthenticatorRawPrefix | `laneboss-e2e-auth-v1:` |

HumanCredential retains AAGUID, AttestationFormat, AttestationMarker,
RegistrationEvidence and identity-derived SimulatedPresence. Registration
verification extracts AAGUID from the actual attested authenticator data and
format/key/algorithm from the verified registration. The declared marker is an
explicit EnrollmentValidationRequest field, retained with the private exact
registration request/attestation bytes. It is not hidden in ClientDataJSON,
Algorithm, Source, an ID, or a get assertion. The reserved AAGUID and marker must
occur together, with SimulatedPresence=true. A missing/changed half refuses;
any legacy fixed credential ID/raw-ID prefix also identifies the test device
and cannot silently become hardware by dropping new metadata.

ValidateCredentialPresence is compiled against the dedicated tag. An untagged
build refuses every marked credential during enrollment and verification,
including a revoked credential in startup inventory. There is no configuration
flag, environment override, faults-tag alias or signature shortcut. Only the
test build includes the stand-in's signing/authenticator implementation in its
own fixture package. The shared production code contains identifiers/refusal
logic, not a software signer. The tagged path still requires actual registration,
origin/RP, challenge, signature, UP/UV and monotonic counter verification.

Every VerifiedHumanProof and returned/event ProofRef carries SimulatedPresence.
validAssertionEvidence compares the marks while retaining the existing exact
HumanConfirmRequest bytes unchanged. ProofUseReceipt, MutationReceipt and
Operation preserve the verified mark. Derived Ticket, HumanSession,
ReadAuthority, ChangeApproval and ChangeReceipt preserve it, including exact
replay/rebuild and deferred completion. ValidateProofPresence compares proof,
reference, use receipt and current enrolled credential; the store performs it
under actual one-use validation, rather than trusting a client bool. A missing
false mark for a declared credential refuses. For a result depending on several
approvals, simulated provenance is retained if any consumed authority is
simulated. A launch's retained ticket/proof authority keeps this audit chain.
Dashboard, review, serve assertions and reports display presence=simulated and
human_approval=not_proven for every dependent row, including the aggregate report.
No simulated result is a proven human approval or physical-presence test.

#### 3. Causal revocation before transport invalidation

Decision: lifecycle/store first commits revocation. Authenticator.RevokeLaunch
keeps its existing ID-only signature and is an invalidation/reconciliation step;
it cannot create an unaudited revocation. The control transaction commits the
revoked launch binding and endpoint, current cancellation epoch/continuation
cancellation and actual identity.revoked event under its original request,
operation and requester. IdentityStore.LaunchRevocation(ctx, launchID) is a
protected lookup of that retained LaunchRevocation record and event, including
the actual JCS record digest and committed sequence. An unrevoked/missing event,
changed target or fabricated service label refuses.

Assembly binds Server's ConnectionInvalidator to identity with BindConnections
after construction. Identity validates/read-backs the committed revocation,
then InvalidateLaunch closes every bound connection and streaming/pending
delivery for that launch, including old endpoint generations. The transport
returns TransportInvalidationReceipt with the same event/operation and known
remaining connection/delivery counts. Nil/unknown/nonzero is incomplete.
RevokeLaunch returns nil only after validated close completion. Store
authorization already refuses new work after the commit; close failure remains
a retained pending effect stage for retry. Restart reconciles that same cause
and event; it does not un-revoke or invent another manual operation. Invalidation
does not prove process quiescence, release a UID/credential or collect a helper.

#### 4. Worker endpoint bootstrap identity

WorkerIdentityStore.WorkerBinding(ctx, installedBinding, nativePeerFacts) is a
protected reverse lookup before worker authentication. It joins the installed
WorkerLeaseID and launch/endpoint with the real current job stage, worker
LaunchRecord, helper UID/containment/boot/allocation, pinned connector lifetime,
current effect claim/generation, cancellation epoch, expiry and grant set.
WorkerPrincipal retains that tuple, including StageID and optional
CaptureBindingID. ConsumedBy on an active WorkerLease names its actual worker
LaunchRecord.ID. A copied lease or supplied PeerFacts does not authorize this
port; only installed identity uses it after the native verifier. The store must
reload its authoritative job/helper records, not echo request facts.

The resulting Actor is worker with its own principal, zero agent level/role and
the job's real target. It is never relabelled as RequestedBy, lane, human or
root-ticket authority. The launch leader and a verified descendant connector
may have different process generations; the peer registry proves current
containment and pins the connector's actual lifetime, and each frame pins its
actual writer. Old boot, reused UID/PID, passed-descriptor writer, revoked
endpoint/lease, changed claim/epoch and lost expiry refuse before job data.
Capture workers resolve the actual CaptureBindingID through this lookup, so
CaptureState does not have to authenticate its own bootstrap.

| Fixed job kind | Permitted WorkerOperation |
| --- | --- |
| capture | capture.state, capture.append |
| channel, usage | input.read, object.read, result.append, credential.inject |
| materialize, test, import, export, archive, render, box_run, owner_sheet, gateway | input.read, object.read, result.append |

These names select private fixed operations, not new public Methods. Object
access is restricted to that sealed input/job's grants and actual output class;
credential injection still needs the exact enrolled authorized handles. Unknown
kinds/operations refuse. Native/current job checks run again on every frame and
delivery. ValidateWorkerPrincipal establishes correlation, not kernel evidence.

#### 5. One guidance evaluator, await and recovery

ReserveGuidance remains the one private atomic selector for (config, life,
logical turn), retaining task/policy/candidate snapshot across request keys,
restart and profile continuation. Its request adds a fresh internal AttemptID,
ExpectedTurnGeneration, CancellationEpoch and authoritative positive MaxCostMicros.
No public caller selects those authority facts. The store reserves under the
actual pending public receipt, current turn CAS and life epoch, allocates one
ClaimID, and records OwnerAttemptID, OwnerOperationID, OwnerRequestID, OwnerKey,
RequestedBy, original Target, TurnGeneration and BindingItems.

Acquired is an invocation result, true only on the atomic creation winner and
never retained as replay authority. Every observer, same-key retry or repeated
AttemptID returns Acquired=false. GuidanceCanEvaluate requires both Acquired
and the matching attempt plus exact retained inputs/deadline. Equality with a
first response or a nonempty ClaimID is not winning ownership. Same-key public
retries first await/replay their existing receipt; other keys use the protected
AwaitGuidance(ctx, scope, {ReservationID, Deadline}) handle, then seal their own
reply with the same completed selection. Timeout does not rejudge or take over.

Reservation status is pending (Generation=1, no Result) or completed
(Generation=2, one Result, Acquired=false). ClaimID and original owner facts
remain immutable audit data. The total Deadline is fixed at creation, at most
five seconds after ReservedAt; no retry/batch resets cost or time. Result status
is the existing scored/empty/unavailable vocabulary and all frozen turn/input
pins and binding items must agree. Profile continuation may read the same
logical-turn selection but cannot acquire a second evaluator for the new run.

Normal InternalGuidanceComplete uses the original owner's attempt, operation,
requester/request, target/turn and cancellation epoch. ValidateGuidanceCompletion
and the store compare them with the retained claim. GuidanceSelection adds
AttemptID; Transact requires CompareGuidance against the pending revision and
the exact cancellation guard. Only one CAS can commit the result, Turn pointer
and one guidance.selected event. Public guidance.select remains reply-only.

For an interrupted owner, the scheduler waits out the remaining fixed deadline
(at most five seconds), then InternalGuidanceRecover uses the original cause
and the same CAS/epoch to finish unavailable once. It preserves all BindingItems,
adds a truthful Notice, and has no new judgment IDs or weighted score. No owner
replacement or second provider call is allowed. A completed claim replays;
manual cancellation/changed epoch refuses instead of reviving the turn. An
unknown state is an integrity/shape failure, never an empty successful selection.

#### 6. Fixed administrator registration entry and inventory

The optional protected Installation.admin_enrollment is AdminEnrollmentEndpoint:
config, canonical private socket, dedicated service UID, installation generation,
pinned helper executable, fixed HTTPS origin and RP ID. It is distinct from the
public human/lane/worker listener. Assembly passes it to store and Server; the
service creates the administrator-only control endpoint under protected ownership
and ACLs, outside lane reach. Missing installation makes enrollment unavailable,
not an automatic setup. The source's port/listener implementations remain owned
by admin/service; an optional boot field does not advertise a running ceremony.

The fixed entry is the existing internal helper mode, implemented by lb-v2-admin:
`laneboss internal helper --config NAME --installation FILE --enroll-begin FILE`
and its mutually exclusive `--enroll-complete FILE` form. The administrator runs
that installed helper as the local administrator account (root on the supported
Unix backends); the ordinary event service stays its dedicated unprivileged UID.
The helper verifies the protected installation/helper digest and connects to its
private administrator socket. Both ends verify the real kernel peer, artifact
and installation generation. Root login identity alone grants no human proof.
No lane/public RPC can carry these messages or serialize an InternalIntent.

AdminEnrollment.BeginHumanEnrollment calls identity's EnrollmentValidator.
BeginEnrollment reserves an unpredictable one-use EnrollmentChallenge through
EnrollmentCeremonyStore.ReserveEnrollment, with protected origin/RP/endpoint and
installation generation, principal/config, ceremony ID and a five-minute maximum
expiry. It returns the actual WebAuthn create challenge. The administrator's
browser/authenticator at that origin produces ClientDataJSON and AttestationObject;
only public attestation bytes and the declared marker go into the complete file.
The private key stays solely in its authenticator/test directory.

CompleteHumanEnrollment calls ValidateEnrollment, which loads that exact stored
challenge, verifies real webauthn.create/attestation, origin/RP/nonce, key and
algorithm, flags/counter and the reserved marker rules, and retains private
immutable registration evidence. It derives HumanCredential and an
EnrollmentInstall carrying CeremonyID, ChallengeID, ValidationID and expected
generation. ValidateEnrollmentInstall checks this handoff; it is not a substitute
for cryptography. ValidateInitialEnrollment additionally restricts the fixed
complete entry to ExpectedGeneration=0. Under the writer lock, admin_enroll
requires the complete configuration-wide inventory to be absent (including
revoked prior enrollments), rechecks the genuine administrator channel and
identity validation, consumes the create challenge and atomically commits
Enrollments, exact Objects and ceremony/operation receipt. A new principal ID
does not reopen this baseline exception. Later validated registrations are
proposals through the existing human/D6 approval path and its current guards.

EnrollmentReceipt retains actual config/principal/generation, ceremony/challenge,
private evidence, operation, event and committed sequence, plus SimulatedPresence.
The referenced event is the actual blob.committed/operation commit in that atomic
admin_enroll transaction; no synthetic enrolled event or direct database seed.
Lost replies replay the same ceremony receipt. This entry is a contract for its
owners, not permission for this executor to enroll a credential or run a helper.

HumanEnrollmentInventory.HumanEnrollments(ctx, config) is the required protected
complete store read, including revoked credentials, with no caller-selected
principal/path/SQL and no public RPC. IdentityStore embeds it. Assembly calls
CheckHumanEnrollmentPolicy before constructing/listening on any service endpoint;
missing/error inventory stops startup in every build, and untagged marked data
stops production. Store construction must enforce the same guard before starting
background effects. Initial principal resolution continues to use the real
installed human endpoint; an empty Actor.ID on that lookup is intentional and
does not authorize ordinary label-only scope reads.

#### 7. LP-LINUX-PLAN-READ-1

LaunchControlSource now includes Plan(ctx, reservationID). The installed Server
resolves its current durable planning/open/recovery claim and calls the same
StateStore.LaunchPlan under its bound private service authority. Linux cannot
invent Scope or infer the retained plan from a supplied LaunchSpec. ReadLaunchPlan
calls that port, preserves its actual error, validates the record and rejects a
foreign reservation selector. Prepare requires spec_retained; bound/opened
recovery reuses its retained gate as already frozen. No local launch-ID map,
fallback plan or new public read is added. Darwin uses the same source contract.

#### 8. LP-CAPTURE-IO-1 outside usage authenticity

Decision: a primary stdout pipe proves capture provenance, not that a quoted
vendor-shaped quota message came from the vendor. A new Claudock LimitSignal
requires UsageEvidence referencing a private committed usage_window envelope.
The CredentialBroker owner's separate UsageWindowSource.ReadUsageWindow receives
the causing target/launch/operation, from-profile grant/handle/provider, actual
run end and pinned adapter/executable/runtime; it never uses the destination's
room or Room.Available=false as exhaustion. Assembly supplies this source to the
Claudock adapter; missing support stays an owning typed failure.

The fixed outside credential/usage worker has kind usage, the protected worker
mapping above, its own narrow grants, and the enrolled Claudock usage executable.
It runs `claudock usage --max-age 0` without a shell under the selected from-profile
credential mapping, a bounded timeout of at most 60 seconds, and no lane writable
home/PATH/settings source. It retains the exact private stdout and actual exit.
The pinned v1 source is TSV with exactly PROFILE, PLAN, WINDOW, USED_PERCENT,
RESETS_UTC columns. The source resolves vendor profile spelling from protected
profile enrollment. The header, every row's finite/nonnegative usage, reset
encoding and consistent PLAN are validated; failed/partial output is unusable.
Unknown resets may remain diagnostic rows, but cannot prove a live exhausted
window. No guessed alternate JSON record or fake window is accepted.

UsageWindowEvidence binds schema laneboss.usage-window.v2, causing IDs and
from-profile/provider, executable/adapter/runtime, actual worker lease/principal/
kernel generation/boot, exact raw bytes/hash and row, observation time, window,
usage percentage, reset and exit. ValidateUsageSource compares actual TSV fields
and hash with the normalized envelope. ValidateUsageWindow requires the genuine
usage worker mapping, a successful measured command, UsedPercent>=100, a known
future reset, observation after the actual run end and no more than 30 seconds
old. Both checks and actual ACL/producer/enrollment checks are required. Cooldown,
auth failure, unknown reset, stale cache, foreign profile and lane-local bytes
cannot produce a signal. Exact worker/job results survive restart; a stale
measurement is refreshed outside, not relabelled as current. This freezes the
usage-window portion only; interactive attach, arbitrary split vendor framing,
companion/adoption and independent live mode receipts remain their own gates.

#### 9. LP-DATA-JOB-1 materialization within PlanLaunch

Materialization is one durable child Worker effect of the current PlanLaunch
claim. Under that parent claim the planner/store allocates a distinct StageID,
worker effect/lease, narrow job GrantSet and immutable materialize_input once,
and retains LaunchPlanRecord.DataStageID under plan CAS/epoch. The same sourced
reservation, original operation/requester/request and agent HelperLeaseID remain
pinned. The public request still supplies no stage IDs, executable, path or claim.
StateStore.LaunchDataStage reloads that exact retained stage by LaunchDataRequest;
absence/unknown state never authorizes deterministic IDs or reallocation.

The installed service's MaterializationControl.MaterializationStage resolves
that parent, schedules/claims the child with the existing EffectStore and starts
the fixed confined worker through actual register/prepare/identity/permit/open
steps. It returns the retained launch-time LaunchDataStage, including the real
claim, fixed WorkerPlan, worker/process identities and opened-storage projection;
it waits without holding the writer lock. The service outbox owns that claim.
DataWorker.MaterializeLaunch consumes the returned stage and AwaitMaterialization;
it never steals another planner's claim, scans PendingEffects for guesses or
executes copy/Git as the service account. The job's RunInternal implements the
actual confined copy/Git/home preparation. Restart reads the original stage and
gate; a retained launch-time claim snapshot is not new execution authority.

The job GrantSet is distinct from the agent's set. It has one read-only granted
project source at /job/source and no resource / secret / profile / network / channel
capabilities. Source object/hash/history scope and parent grant match the original
reservation. Writes are only the exact helper-authorized workspace/home projection,
not a generic grant to another filesystem root. Result Materialization retains
the original agent grant-set ID; the worker's own launch uses its narrower set.

Additional `copy` deliveries use helper-authorized per-grant projections in
`StorageProjection.Copies`, a bounded canonical `laneboss.data-copies.v2` map.
Every entry retains the complete issued DataGrant, original source BlobRef,
selected/rebased ObjectManifest, source/destination kernel identities and a
distinct private copy workspace ID. A file selection names the fixed leaf
`file` inside that private copy root. The service sends only the issued grant
and source object reference, then reloads its authority. The installer prepares
the protected `sources/<sha>` cache for project trees and tree/snapshot copy
sources explicitly named by the initial root-grants manifest; unrelated
inventory manifests do not become sources. The helper reads manifest and
artifact bytes from that protected cache, independently compares each entry
to its original allocation and verifies all
manifest/content hashes, relative selections, expiry and shared byte limits.
No transport field selects a host pathname.

The production installer limits each source manifest to 1 MiB, each assembled
file to 64 MiB, and the aggregate file content of the project and all copy-source
trees to 64 MiB. These cache ceilings apply to the full installed trees before
grant selections are rebased. The protected initial publication has a separate
limit of 512 objects and 64 MiB of total object bytes. A larger lane disk budget
does not raise any of these installation limits.

The 65 MiB assembly native copy proof uses a test-only override of
`boot.MAX_OBJECT` to 256 MiB in
`source_cache_canary.py`, together with a 256 MiB test
disk budget. Its large-assembly coverage uses that explicit fixture setting;
the production installer retains the ceilings above.

The helper holds a fresh source/destination descriptor pair for every copy.
The fixed worker receives those sources read-only at `/job/source-<grant-id>`
and job-only writes at `/job/copy-<grant-id>`. It hashes and copies every
selected tree and acknowledges one identity/hash receipt per original data
grant. The outside helper verifies those actual bytes through the same held
roots before returning them to the lane. Lane exports use the held destination
descriptors at the original `/work/<id>` or `/data/<id>` destinations, with
read-only binds for `ro` and independent writable copies for `rw`. The main
project remains the unique `copy` source at relative path `.`; the job receives
no agent credentials or generic source/root access. Missing projections or
receipts, changed IDs/hashes/rights/destinations and expired entries refuse.
Unimplemented delivery modes retain a typed Unsupported naming the mode.

An export requires a measured job and its original live descriptors in
`m.dataPins`. After a helper restart those descriptors are lost: preparing a
lane gate requires re-materialization, and neither a journal entry nor a
known path can reconstruct the export. A replay of an existing live token
matches the held projection, including its historical expiry; a new or still
reserved preparation checks current expiry before staging any copy roots.
Failed preparation removes both newly created copy roots beneath their held
protected parents, including a final projection-validation or journal failure.

The lane mount builder makes `/work/main` read-only whenever its project grant
is `ro`, for every lane. Repository-owned bootstrap and runner preparation do
not write that mounted project; materialization writes `/job/workspace` before
the lane gate, and private runner records use the lane home/history. The native
copy observer reads the project and proves write refusal. External vendor/tool
behavior is not established by this source audit.

The retained per-copy destination identities also participate in private
storage inventory, withdrawal and final collection. Only the original three
workspace/home/history roots share the 4096-entry `OriginalModes` journal.
Copies are excluded from that journal and have an independent 4096-entry
withdrawal walk per root, also enforced at copy admission. A writable copy
that later grows beyond that bound makes `retainPrivateStorage` return at the
first failing root, leaving the lane's `Storage.Withdrawing` true and
`Storage.Withdrawn` false. Remaining roots are not processed, and earlier roots
may already be retained. This lane-wide failure requires administrator recovery,
as with the workspace bound. The existing aggregate private collection inventory
bound still applies. Data-source
collection inventories all staged source roots together, admits only the
collector's own held descriptors and removes every source before withdrawing
the worker's traversal group. Collection never reconstructs a live export.

Admin.OpenLaunchDataStorage receives only stage/reservation/agent lease/worker
lease IDs. It validates the current journal, opens and holds descriptor-pinned
source/workspace/home roots, and returns StorageProjection with OpenToken,
generation, actual kernel identities and immutable evidence. OpenToken resolves
those held descriptors in the protected helper registry, never a reopenable
caller path. Prepare projects the same roots read-only at /job/source and with
job-only writes at /job/workspace and /job/home, using a distinct worker UID/
containment and bounded scratch. It seals the read-only binding at
/runtime/laneboss-worker.json. Missing/replaced/old-boot handles stop; no process
accepts client-passed descriptors or turns registry labels alone into open files.
The helper keeps pins until actual job/agent ownership and collection permit
release. The data worker cannot read service state, canonical org or credentials.

WorkerPlan uses laneboss.worker-plan.v2, kind materialize and the installed
laneboss worker executable. Its fixed argv is
`laneboss internal worker --binding /runtime/laneboss-worker.json --lease ID`.
The private worker endpoint implements WorkerBootstrap.WorkerInput and
WorkerResult only after item 4's native mapping. WorkerJobInput includes exact
sealed bytes and stage/lease/kind/operation/effect/ref; ValidateWorkerInput checks
all of them. WorkerResultSubmission carries the same lease, expected revision,
input hash and bounded actual output bytes. For materialize the output is exact
JCS LaunchData. Service strictly decodes that job's closed output, retains its
bytes once and returns a WorkerResultReceipt with hash/reference/revision/sequence.
A changed retry conflicts. This acknowledgement does not claim process exit.

The outside supervisor observes the same retained ProcessHandle to exited/zero
survivors, reopens/read-backs the exact projected output, and verifies the
materialization manifest, source/destination identities, workspace/home and
original input/grant/base. LaunchDataResult binds that observation, real result
acknowledgement and exact acknowledged Data bytes to the same stage/effect/cause.
ValidateLaunchDataResult checks those pins, successful known exit, zero survivors
and manifest read-back hash. CompleteEffect commits the measured result once;
only then AwaitMaterialization returns success and the planner advances to its
planned phase. Failure/cancellation/unknown process or output remains typed and
retained. Replays read the same result and actual bytes, never launch another job.

Owners are service/store/outbox for stage/claim/receipts, admin for opened storage
and fixed runtime projection, identity/native peer for worker binding, and grants/
dataworker for the confined job and measurement validation. Assembly now passes
installed Config and MaterializationControl to dataworker, Config/Human to grants,
the enrollment validator to service, and the transport/enrollment binders to
identity/admin. These additions do not implement those owners' native backends.

#### Added field maps and regression handoff

| JSON object | Complete field map |
| --- | --- |
| AdminEnrollmentEndpoint | `{config: string, socket: string, service_uid: integer, installation_generation: integer, origin: string, rp_id: string, helper: Executable}` |
| EnrollmentCeremonyRequest | `{config: string, ceremony_id: ID, principal_id: ID, expected_generation: integer}` |
| EnrollmentValidationRequest | `{ceremony: EnrollmentCeremonyRequest, challenge_id: ID, client_data_json: bytes, attestation_object: bytes, attestation_marker?: string}` |
| ProofUseReceipt | `{proof_id: ID, credential_id: ID, nonce_id: ID, operation_id: ID, used_at: Timestamp, simulated_presence?: boolean}` |
| WorkerInputRequest | `{lease_id: ID}` |
| WorkerJobInput | `{schema: "laneboss.worker-input.v2", stage_id: ID, lease_id: ID, kind: string, operation_id: ID, effect_id: ID, input: BlobRef, bytes: bytes}` |
| WorkerResultSubmission | `{lease_id: ID, expected_generation: integer, input_sha256: Digest, result: bytes}` |
| WorkerResultReceipt | `{lease_id: ID, stage_id: ID, generation: integer, result: BlobRef, committed_seq: integer}` |
| UsageWindowEvidence | `{schema: "laneboss.usage-window.v2", id: ID, target: LifeRef, launch_id: ID, operation_id: ID, profile_grant_id: ID, profile_id: ID, provider: string, adapter_version: string, executable: Executable, runtime_manifest: BlobRef, worker_lease_id: ID, producer_id: ID, producer_generation: string, boot_id: string, observed_at: Timestamp, window: string, used_percent: number, resets_at: Timestamp, exit_code: integer, raw: BlobRef, row: integer}` |

The following additions are Go-only private ports/projections, not public Params:

| Type | Members/additions |
| --- | --- |
| HumanCredential | Existing ID/raw key, algorithm, counter, generation and revocation plus AAGUID, AttestationFormat, AttestationMarker, RegistrationEvidence, SimulatedPresence. |
| VerifiedHumanProof, MutationReceipt | Add SimulatedPresence; all original exact evidence/authority fields remain. |
| ReadAuthority | Add Generation, SimulatedPresence; StoredReadSession retains its revision and HumanSession's mark. |
| ReadSessionRefreshRequest, ReadAuthorityUpdate | SessionID/ExpectedGeneration; Before/After respectively. |
| EnrollmentChallenge | ID, Ceremony, Challenge, Origin, RPID, EndpointGeneration, InstallationGeneration, ExpiresAt, Consumed. |
| EnrollmentInstall | Existing Enrollment, ExpectedGeneration and CeremonyEvidence plus CeremonyID, ChallengeID, ValidationID. |
| EnrollmentReceipt | CeremonyID, ChallengeID, PrincipalID, Config, Generation, Evidence, OperationID, EventID, CommittedSeq, SimulatedPresence. |
| LaunchRevocation | Record, RecordSHA256, Cause, EventID, CommittedSeq. |
| TransportInvalidationReceipt | LaunchID, RevocationEventID, OperationID, RemainingConnections, RemainingDeliveries, CompletedAt. |
| WorkerPrincipal | StageID, Lease, Record, Endpoint, Peer, BootID, AllocationGeneration, Claim, CancellationEpoch, CaptureBindingID. |
| GuidanceReservationRequest | Adds AttemptID, ExpectedTurnGeneration, CancellationEpoch, MaxCostMicros. |
| GuidanceReservation | Adds Config, TurnGeneration, Acquired, OwnerAttemptID, OwnerOperationID, OwnerRequestID, OwnerKey, RequestedBy, CancellationEpoch, MaxCostMicros, BindingItems. |
| GuidanceSelection, GuidanceAwaitRequest | Adds AttemptID; await has ReservationID/Deadline. |
| UsageWindowRequest | Target, LaunchID, OperationID, ProfileGrantID, ProfileID, Provider, RunEndedAt, AdapterVersion, Executable, RuntimeManifest. |
| StorageProjectionRequest | StageID, ReservationID, AgentLeaseID, WorkerLeaseID. |
| StorageProjection | StageID, Storage, WorkerLeaseID, OpenToken, Generation, SourceIdentity, WorkspaceIdentity, HomeIdentity, Evidence, optional Copies (canonical private copy-projection map). |
| DataCopyProjection | Grant, Source, Manifest, SourceIdentity, DestinationIdentity, WorkspaceID, optional File (`file`). |
| LaunchDataStage | ID, Reservation, Inputs, Grants, AgentLeaseID, ParentEffectID, Claim, Worker, Plan, Storage, WorkerLaunchID, Process. |
| LaunchDataResult | StageID, WorkerLeaseID, EffectID, OperationID, InputSHA256, Data, Manifest, ReadBackSHA256, Observation, ResultReceipt. |

The public method catalog and existing write fields/events/effects remain closed.
Guidance writes gain an unconditional claim-CAS/cancellation shape check; no
public selection write authority is added. New private store methods are atomic
authority operations only as specified above, never permission from an ID or a
serialized service label. admin_enroll remains the existing initial/policy
approved row. JSON/event maps above propagate presence; exact assertion-object
bytes and existing trusted event emitters are preserved.

| Item | Regression and deciding refusal | Consumer adaptation |
| --- | --- | --- |
| Idle activity | TestSessionRefresh, TestSessionAuthority reject expired/revoked/cross-connection or changed absolute expiry/revision and prove the absolute cap. | identity/store implement atomic refresh; transport implements serialized same-session refresh; dashboard/client snapshots refresh on that connection. |
| Test presence | TestCredentialBuild, TestCredentialMarkers, TestProofMark and TestAtomicPresenceMark reject untagged use, partial pairs and changed proof/receipt marks. | identity/serve use the exact constants/tag; store checks current credential marks; all ticket/session/approval/report/review consumers preserve and display simulation. |
| Revocation | TestRevocationGate recomputes valid record hashes while testing unrevoked records and rejects foreign cause/event or unknown/nonzero close counts. | lifecycle/store commit first; identity reads the retained cause and waits for service transport completion; admin collection remains separate. |
| Worker identity | TestWorkerBinding, TestWorkerInput, TestWorkerResult reject foreign lease/kernel/principal/endpoint/claim, illegal operation and changed sealed input/result bytes. | identity/service/native peers implement protected mapping and private bootstrap; grants/admin/capture/channel/usage workers use their own principal. |
| Guidance | TestGuidanceOwner, TestGuidanceRecovery, TestGuidanceWrite reject observed/replayed ownership, rejudge/foreign cause/early recovery and missing CAS/epoch. | guidance consumes Acquired and await; store/outbox enforces one winner/result/event and no rejudge; judge receives the positive authoritative total budget. |
| Enrollment | TestEnrollmentInventory, TestEnrollmentCeremony, TestEnrollmentEndpoint, TestEnrollmentBaseline reject foreign inventory/challenge/evidence, relative endpoint and replacement via the baseline entry. | admin/identity/service implement the actual private create ceremony and complete inventory; assembly performs startup policy checks; serve uses actual receipts, never inserts keys itself. |
| Plan read | TestPlanReadGate calls the source and rejects a foreign retained plan while preserving source errors. | service implements Plan under its durable claim; Linux/Darwin use ReadLaunchPlan and retain their existing phase/gate checks. |
| Outside usage | TestUsageWindow and TestUsageSource reject wrong, stale, from-destination, non-exhausted or forged producer/reset/failed commands and actual TSV mismatches with rehashed bytes. | secrets/credential worker produces real outside evidence; Claudock/watchdog validate and retain UsageEvidence; packaging/admin pins usage runtime. |
| Data stage | TestDataStage and TestDataResult reject parent-claim reuse, input/argv/open/storage/epoch or widened grant drift, foreign run/process/operation, nonzero exit and source/read-back mismatch. | service/store/outbox exposes original stages and actual completion; admin supplies held roots; identity authenticates the fixed job; dataworker performs real copy/Git/home work inside it. |

Every deciding control must first compile, then fail its named reached assertion
for the intended diagnostic on Linux and pass the same candidate assertion.
Static vet/byte-compilation establishes no runtime red, hardware presence or
physical filesystem/process proof. Installed acceptance still requires actual
session-refresh races, revocation close/restart, worker UID/kernel/capture mapping,
two guidance request keys with one evaluator/event and interrupted recovery,
real registration/signatures with production refusal and simulated reporting,
fresh outside usage versus a harmless lane writer, and materialization copy/Git
read-back/restart under the real installed boundaries.

#### 10. One policy-generation rule across D6 changes

Generation is selected by the operation, not by equality with a lane's old
launch label. PolicyGenerationFor defines the closed private modes below:

| Operation | Generation to use |
| --- | --- |
| New evaluation | Current approved policy, including its current cache key, rules, judge/context and limits. |
| Fresh guidance selection with no prior turn claim | Current approved policy; reserve that generation with the new one-winner claim. |
| New start/adopt/resume/turn/continuation launch | Current approved policy and newly resolved/revalidated grants/eligibility; fresh plan/spec binds that generation. |
| Exact completed receipt replay | Generation retained with the actual receipt/result, after current authentication, revocation and receipt visibility checks. Never re-evaluate or consume proof again. |
| Existing pending/completed guidance claim | Original immutable claim/selection generation and inputs. Await/complete/recover/replay that claim once; never create another evaluator because a D6 generation changed. |

StateStore.Policy returns current approved policy; Scope.PolicyGeneration is the
current effective authorization context for new work, not a request to load the
launch-time snapshot. Identity must not reject an otherwise current authentic
running lane merely because Lane/LaunchRecord/issued grants record an older
generation. It checks actual current authority and revalidates capability
ceilings/revocation under current policy. Issued GrantSet and LaunchRecord
generations/hashes remain historical issuance/launch facts; no byte/digest is
silently rewritten to make a comparison pass.

MutationReceipt adds PolicyGeneration, stamped by the store from the policy used
for that operation. PolicyGenerationForReplay checks the exact config/actor/key/
digest and chooses that retained generation. PolicyStore.PolicyAt is a protected
read of an actual immutable approved snapshot for receipt/selection verification;
it is not a public way to choose an older policy for a new action. A completed
guidance result under generation 3 can replay after current generation 4,
including to another request key observing the same logical-turn selection.
Its reply and binding snapshot remain historical evidence, not permission to
execute a new command under generation 3. Current binding policy still governs
every subsequent action. A pending owner may retain an already-issued measured
judgment; if current authorization/provider/budget revocation prevents remaining
work, finish unavailable under the same claim, with no fallback or rejudge.

For fresh work, the service resolves current policy before building judge
context, selecting fresh guidance or constructing a new launch. ResolveJudgeForScope
keeps its same-generation comparison: callers now pass the freshly resolved
scope/context. A new launch resolves a fresh reserved grant-set snapshot at
current policy; it does not compare the previous run's historical issuance
generation to current and stop there. Revalidate the actual requested/current
capabilities and preserve logical task/history/budget. ValidateLaunchPolicyCurrent
checks the new reservation and its issued set immediately before execution.

The live Lane.PolicyGeneration projection advances through the protected
PolicyStore.RefreshLanePolicy operation, emitted by the service/store policy
coordinator on first fresh evaluation/selection/launch after lookup has proved
this is new work. Identity's pre-replay authorization only resolves current
authority; it does not alter the retained receipt or rescore it. Under current
policy/grant/epoch and CompareLane, the coordinator increments Lane.Generation,
sets PolicyGeneration to current, and emits exactly one service-origin
lane.policy event with from/to policy generations, new lane generation, policy
hash and unchanged grant-set ID. InternalKind policy_refresh writes only Lanes
and that event with a cancellation guard. ValidatePolicyAdvance permits only
those projection changes; validPolicyRefresh requires the event/CAS/epoch tuple.
Already-current refresh is an unchanged receipt without another event. No
existing launch record/spec/grant object, endpoint, role, budget, counter, run or
workspace is changed by this projection update.

Lifecycle/watchdog refresh before taking their launch/eligibility/claim fences;
human challenge callers refresh/reload the current base before requesting an
operation proof. A concurrent policy advance can legitimately invalidate a
submitted old life CAS/proof base; return conflict and reload, not a permanent
generation-mismatch refusal. Actual revoked/narrowed authority, an explicitly
stale expected policy/base, unknown or future retained snapshot, changed digest,
cancelled epoch and policy changing after an immutable plan was sealed also
refuse. For the last case, reconcile/abort the unopened retained plan and keep
its original failed receipt; obtain a fresh authorized reservation rather than
editing the old digest or opening it anyway. Reconciliation of an already-opened
process reads its historical binding while enforcing current control rights.

Policy adapts evaluation/cache/context to current policy while preserving exact
replay; guidance looks up the retained turn claim before fresh-generation/task
preflight; lifecycle distinguishes historical prior-run inputs from fresh plan
authority; watchdog refreshes current policy and fences before selection/slot
handoff and never treats a stale generation as no-room or permission to rotate.
Identity/grants/store and native gate consumers apply the same current-versus-
historical distinction. No existing row's authority is widened.

| Added private type | Members |
| --- | --- |
| PolicyAdvanceRequest | Target, ExpectedLaneGeneration, FromGeneration, ToGeneration, CancellationEpoch. |
| PolicyAdvanceReceipt | Changed, Lane, Event, EventID, CommittedSeq. |
| PolicyAdvanceEvent | JSON `{from_generation: integer, to_generation: integer, lane_generation: integer, policy_sha256: Digest, grant_set_id: ID}`. |
| PolicyStore | PolicyAt(ctx, Scope, Generation); RefreshLanePolicy(ctx, Scope, PolicyAdvanceRequest). |

TestPolicyUse covers current evaluation/selection/launch and retained receipt/
selection separately; TestPolicyReplay reproduces a generation-3 receipt under
current generation 4 and rejects a changed digest. TestPolicyAdvance and
TestPolicyAdvanceWrite reject widened projections, wrong events and missing
life CAS/epoch. TestLaunchPolicyCurrent requires current continuation inputs
and rejects an old sealed unopened plan. Each case has a deciding red control;
installed D6-mid-run evaluation, guidance replay and continuation remain required.

#### 11. Raw hook files cannot erase decision exit status

Decision: org hook's raw --request form is unsupported. The common Run path
returns typed unsupported owned by lb-v2-policy, exit 69 and no result output,
before invokeFile can return a successful RPC as exit 0. The hook's help text
states that restriction. The ordinary decision-aware hook adapter retains its
deny/nonzero behavior and its existing owner implementation requirement. Other
RPC file forms and org hook-history remain unchanged. TestHookRawFile goes
through cli.Run and requires this exact typed refusal; its control removes the
actual guard. No transport/setup error or a successful deny reply counts as
that refusal. Policy/common CLI consumers must use the hook adapter for hook
execution and must not invoke a decision-returning RPC then discard the decision.

### Draft.4 fix 12: native credential projection handoff

This addition closes the credential handoff contract needed by standard agent
Prepare. Acquire, Inject and InjectWorker still select only already-authorized
profile or task credentials. The fix-9 launch plan, fix-10 authority gates and
fix-11 worker mapping, materialization and policy decisions retain their existing
meaning. A logical CredentialSlot or Injection is not proof that a helper holds
credential material. No new public RPC, launch phase, source pathname, arbitrary
argv, backend selector or credential blob class is introduced.

#### Native transfer and ownership

CredentialProjectionRequest binds the current helper_prepare Cause and
EffectLease to the complete retained PreparedSpecHandoff, its nonexecuting
PreparedLaunch, actual HelperLease and PrivateHomeBinding. Worker requests also
carry the actual WorkerLease and the selected WorkerCredentials read from the
protected job and enrolled runtime. An ID alone or a caller-provided list never
authorizes a source. The helper already owns the closed bootstrap gate when it
requests this transfer; it does not return a successful Prepare until the
credential receipt below is committed. Existing runner-local verification of
Acquire's slot remains a broker capability check, not evidence that helper
projection has occurred and not a way to open the gate early.

CredentialProjectionIdentity.AuthorizeCredentialProjection accepts the actual
VerifiedPeer of a distinct private native control connection. It pins the
installed root helper, outside credential worker and both kernel process
lifetimes, boot, installation generation and actual configuration. The broker
UID is distinct from root, the event-service UID and the lane UID, and its
containment is outside the lane. Linux validates each recvmsg writer and pidfd;
Darwin validates the audit token, executable and retained process lifetime for
each message. The ordinary lane or human frame reader still rejects ancillary
descriptors. The credential channel is private to the enrolled helper and
credential worker and is never mounted into a lane or exposed as a public method.

CredentialProjectionBroker.TransferCredentials resolves the existing selected
slot or injection under its canonical refresh lock and the current stored
claim, grants, source versions, revocation and cancellation fence. It returns
CredentialTransfer: one ordered anonymous descriptor per derived CredentialTarget
and a CredentialProjectionAuthority. ReserveCredentialProjection commits the
unique prepared-gate record before any descriptor export. On a partial or lost
reply, CredentialProjection(ctx, config, preparedID) selects that same record
for reconciliation or withdrawal; an unavailable lookup retains the allocation
and cannot be treated as no exported material. Descriptor transfer is native SCM_RIGHTS,
not a numeric fd in JSON or a path reopened by the service/helper. Source objects
are regular, private, unlinked, immutable for the handoff, read-only and
close-on-exec. The receiver checks exact ancillary count, bounds, truncation,
unexpected control messages, actual fstat identities, access flags, size and
the broker's tracked absence of writable aliases. Linux must seal the source
against writes; Darwin must retain an exclusively controlled unlinked object
with no writer and refuse when that cannot be established. Only descriptors and
bounded private control metadata cross this channel. SecretMaterial and file
contents never enter a generic blob, event, log, argv, worktree, fixture home,
archive or service-UID memory. CredentialTransfer.Files is json:"-".

Ownership is explicit. The broker owns its original export descriptors and the
canonical refresh lease until a durable acknowledgement. The helper owns every
received duplicate as soon as recvmsg accepts it, including partial or refused
transfers, and closes all those duplicates on every failure. It copies only
from the received descriptors into separate helper-created objects under its
held home root; source and destination identities must differ. It never acquires
credentials by reading a source path that a lane can read, and never passes an
escrow descriptor or its path into the child. After copying it closes received
source duplicates and retains one destination descriptor per target. The broker
retains its originals until AcknowledgeCredentials validates the actual helper
receipt and CommitCredentialProjection seals the same record; only then does
the broker close the originals. A lost acknowledgement reconciles that same
projection and object identities. It never blindly exports a new slot or leaks
the first set of descriptors.

#### Closed modes and lane destinations

All file names below are relative to the helper-held private home and are
destinations only. The helper opens beneath the registered root without links,
compares held descriptors with current names and denies alternate mounts,
hard-link aliases or a replaced root. The lane may read its own selected
projected credential; it cannot read the separate outside source or any other
life's home. Host paths and values remain private native facts.

| Selected mode or grant | Fixed destination and use |
| --- | --- |
| codex-file | `.codex/auth.json`, mode 0600, owned by the allocated lane UID, private parent mode 0700. The one canonical login refresh lease remains with the outside worker. Codex may refresh only this run's copy; after real quiescence the broker verifies and serializes any permitted write-back through its existing slot logic. |
| claudock-headless | `.runnerhome-runtime/.runnerhome-token`, mode 0600 in a private 0700 parent, projected read-only. The pinned bootstrap derives only `CLAUDE_CODE_OAUTH_TOKEN` from the held copy immediately before the existing vendor exec. It preserves the enrolled headless registry and settings; no login discovery or second vendor home is imported. |
| Task file delivery | `.laneboss-secrets/` plus the granted clean relative target, mode 0400 with a 0500 parent and an actual read-only confined view. No absolute path, traversal, backslash or NUL is accepted. |
| Task environment delivery | A root-helper-held private buffer or anonymous descriptor, with no lane filename. Apply the exact granted nonreserved value only as the envp of the final unprivileged vendor execve, after the UID and capability drop and completed bwrap/Landlock or sandbox-exec setup. The root helper, bootstrap, boundary program and outer launcher environments contain none of these values. It cannot override home, path, temporary directory, vendor auth, loader, launcher, binding or control variables. |

The `claude-api-key` mode enrolls a Claudock profile backed by an Anthropic API
key. Its fixed destination is `.config/claudock/key-store.json`, relative only
to the helper-held private lane home, at mode 0600 with a private 0700 parent,
one link and the allocated lane UID. The helper writes the pinned Claudock
version/items format from the received selected slot descriptor and requires
the actual read-only confined view. The private registry has exactly one
managed `apiKey` profile plus the vendor-required default subscription entry;
the runner selects that managed profile and explicitly sets the private
CLAUDOCK_REGISTRY_DIR and file: credential-store selectors. Headless profile
and token-record behavior remains unchanged.

This amends api/credential_validation.go:88 from
`item.Delivery, item.FileMode = "env", 0` to
`item.RelativePath = ".config/claudock/key-store.json"`, retaining the initial
`Delivery: "file", FileMode: 0600`. ANTHROPIC_API_KEY remains the single selected
final environment name. A distinct root-owned sealed copy crosses only to the
final unprivileged receiver, which decodes the selected store after UID and
capability drop and completed isolation. Claudock clears inherited credentials,
reads its selected private store and sets Claude's API key variable. Plans,
receipts and records carry names and native object facts, never key values.
Task grants still cannot name this variable or another reserved vendor target.

L6 permits this file only inside that private home during the selected lane
run. It is never a worktree file, capture, harvested artifact or evidence-bundle
input. After measured lane quiescence the helper unlinks the exact tracked
store inode, proves zero remaining links/resources and scans the complete
remaining home and outside retained scopes before releasing the slot. A
must-fail control plants a fake key in harvested artifacts and independently
greps those bytes; a detected or unreadable harvest cannot produce a passing
report. Both harness source flags use one provisioning path: only acquisition
of key bytes differs, and native home bytes differ only in the selected key.
The real-key smoke canary alone has its accepted 60-second wall cap.
A stopped exposed slot follows the same rotation-required receipt and
single-use retirement as headless credentials; it cannot become reusable.

The vendor's children inherit the API key, exactly as they inherit the OAuth
token. A normal `release` retires the single-use slot without requiring
rotation. An explicit containment stop records the distinct `cancelled` reason;
after measured zero descriptors it may retire the non-Codex slot with
`RotationRequired`. A `revoked` fence and every other exposure fence keep the
projection quarantined and block completion until protected rotation. A later
revoke strengthens an unfinished stop: the helper persists its original cause
with reason revoked, and the broker/store persist a monotonic Revoked decision
and the superseded PriorFence with the stronger fence. Both revisions survive
restart verification. Completion checks that decision and authority revocation
even when a stale fence still says cancelled. A later stop or release cannot
weaken revocation, and an executed revoked projection cannot enter stopped
archive collection. Only the ordinary cancelled stop can supply that completed
read-only archive owner.
Codex canonical-seat quarantine remains unchanged.
These are the current exposure and rotation semantics; L6 owns any change to
them. Private delivery does not prevent the vendor or its tools from reading
or persisting their inherited key; the outside scans remain mandatory.

The other declared profile modes remain owner-named not_implemented until their
pinned adapter modes and native delivery are implemented and accepted. There is
no relabeling of helper, API or local modes as the supported shapes above.
CredentialTargets derives the exact destinations from the retained slot and
resolved task grants. Injection's selected GrantIDs and SourceVersions are
correlated by index. Worker selectors instead come from the protected enrolled
WorkerCredentials joined with their WorkerLease and original sealed job input;
they need not be lane SecretGrants. Only the existing channel and usage worker
credential permission is allowed; this addition grants no capture or materialize
worker credential access. Source generations and versions are inventory facts,
not hashes of credential contents.

#### Held proof, opening and withdrawal

The administrator's InspectCredentialTransfer produces actual native
observations of type CredentialDescriptorFact. ProjectCredentials validates
them, performs the fixed
copy or environment staging and returns CredentialProjectionReceipt with exact
prepared gate, spec digest, helper lease, home root and revision, cancellation
epoch, targets and source/destination identities. HeldDescriptors measures one
retained destination descriptor per target; InheritedSources measures zero
escrow descriptors available to the child. GateClosed must be observed true.
ObserveCredentials independently reopens no credential source: it remeasures
the helper's already-held destination objects and their names. Boolean labels,
caller counts or a successful copy call cannot substitute for those measurements.

The store retains CredentialProjectionRecord under the existing causal helper
operation and current effect claim. State moves reserved, held, withdrawing,
withdrawn, with a strictly increasing revision on each transition. A reserved
authority at generation g has a held receipt at g+1; withdrawal first fences
that record and later seals a second measured completion revision. Identity's
CheckLaunchCredentials reads the current protected record and checks its exact
LaunchBindingRequest before a new BindLaunch permit. The API gate validator
also checks retained targets, source versions, receipt and the original home.
It validates fresh opening, not historical identity/replay authentication of
an already-running process. Existing opened-process reconciliation retains its
original permit and never opens a second gate after a claim expires.

Immediately before the existing OpenGate, the helper obtains
LockCredentialProjection with CredentialGateRequest, including the original
HelperOpenRequest and expected projection revision. Its CredentialGateGuard is
a live native broker lock over the source versions and refresh lease. Check
revalidates current protected state and helper liveness. The helper holds it
and its own lease lock through the actual one-use gate/exec acknowledgement,
closing it on every path. A descriptor-bearing control disconnect, expired
claim, stale revision, failed guard or changed source refuses. A DTO receipt is
never a reusable opening token and this guard never replaces LaunchPermit.
The existing outside canonical refresh lease precedes the projection guard;
the guard precedes the helper lease lock, then any short store writer section.
LockCredentialProjection checks ownership of that existing refresh lease and
does not recursively acquire it. No store writer waits for native I/O. The
native control lifetime is bounded; a broken peer releases the guard, refuses
exec and fences the projection.

Refusal, source revocation, expiry, cancellation, release and restart uncertainty
all have a withdrawal path. BeginCredentialWithdrawal validates a
CredentialWithdrawalRequest against the current revision and first closes new
guard acquisition in the broker's protected withdrawal journal. It drains an
already-acquired guard without holding the helper lease lock, then commits the
exact cause and reason through FenceCredentialProjection. That commit is the
withdrawal linearization point; a prior guard either completed its opening
before it or refused. It then orders WithdrawCredentials under the helper lock.
If an agent already executed, use the original StopGate and actual observation;
otherwise AbortGate the original closed bootstrap. There is no unlink-only
substitute for stopping a process. No new gate may start after the fence.

The helper removes the pinned projected files and any replaced names within
the registered private root, destroys its environment buffers, closes its held
descriptors and measures zero process survivors and gate references. Unknown
objects, aliases or uncertain collection retain the allocation and require
rotation; they are not success. It returns only helper-owned measured counts,
leaving broker fields unknown. FinishCredentialWithdrawal independently closes
the outside originals, cancels or completes allowed refresh without accepting
untrusted write-back, releases the canonical refresh lease and fills its own
BrokerDescriptors and RefreshLeases counts. ValidateCredentialWithdrawal requires
the exact persisted fence/cause and known zero counts from both producers before
CompleteCredentialWithdrawal can seal withdrawn. The existing Release and
RevokeInjection additionally retain their real quiescence requirement. Failure
or crash reconciles this same record; no ID, UID, home or slot is recycled early.
Credential withdrawal cannot make a process forget bytes it already read;
canonical credential rotation/revocation remains the broker's required recovery
when such exposure or a changed refresh object requires it.

Normal Codex release has an explicit reverse descriptor port:
CollectCredentialRefresh copies the actual pinned, quiescent auth object into
a new root-owned, unlinked read-only export and returns CredentialRefresh.
AcceptCredentialRefresh authenticates the actual helper VerifiedPeer and takes
its received duplicate directly in the outside credential worker. It remeasures
the descriptor, requires zero survivors and the exact fenced projection, slot
and canonical source generation, then uses the existing pinned Codex credential
validator and serialized canonical refresh lease before any write-back. It never
opens a lane-visible credential pathname as its source. The helper owns its
export until acknowledgement; the broker closes every received duplicate on
success or refusal. Lost replies replay the original refresh receipt; they do
not apply another update. CredentialRefresh.File is json:"-". Refused, revoked,
expired, cancelled or uncertain sources do not write back and retain the
existing rotation/quarantine requirement; a stop received after a natural exit
that is already durably recorded takes the normal release path. Headless and task credentials have no
refresh return. This reverse path is part of withdrawing the same projection,
not a new credential acquisition or a new worker kind.

#### Owner ports and deciding controls

All new types in credential_projection.go are Go-only private control or store
facts; CredentialDescriptorFact and CredentialHeldTarget are native observation
projections, never caller authority. The API validators perform no I/O. They
establish correlation only; real descriptors, kernel peers, confinement, held
objects, zero counts and canonical refresh ownership remain producer evidence.

| Owner | Exact adaptation |
| --- | --- |
| lb-v2-secrets | CredentialBroker now embeds CredentialProjectionBroker: TransferCredentials, AcknowledgeCredentials, LockCredentialProjection, BeginCredentialWithdrawal, AcceptCredentialRefresh and FinishCredentialWithdrawal. Inject, InjectWorker and Acquire retain ownership of their selected material and current source leases until this native handshake completes. Dependencies.ProjectionIdentity supplies the protected identity resolver. Implement the private outside-worker channel, immutable export, acknowledgement, guard and broker cleanup; no raw descriptor returns through the event-service process. |
| lb-v2-admin | HelperControl embeds CredentialProjectionControl: InspectCredentialTransfer, ProjectCredentials, ObserveCredentials, CollectCredentialRefresh and WithdrawCredentials. The first projection-bearing Prepare or recovery Launch invokes BindCredentialProjection with the configured native broker and identity clients; an owner-named refusal propagates before the underlying operation. Binding succeeds once; retry of an error requires the explicit unbound certification below. Prepare must stage and acknowledge the exact held receipt before returning. OpenGate must hold the actual broker guard and helper lease lock. Stop, Abort and Release reconcile withdrawal before reuse. |
| lb-v2-service and store | StateStore embeds CredentialProjectionStore: CredentialProjection(ctx, config, preparedID), ReserveCredentialProjection, CommitCredentialProjection, FenceCredentialProjection and CompleteCredentialWithdrawal. Use the single existing writer, current source inventory, exact service component scope, claim CAS and cancellation fence. Keep a unique durable projection per configuration and prepared gate, and reject changed retries. Store only metadata and private measurements; never Files or values. RuntimeServices now carries Credentials and CredentialIdentity for outbox/recovery coordination. |
| lb-v2-identity | Implement CredentialProjectionIdentity.AuthorizeCredentialProjection from actual native VerifiedPeer and protected installed pins, not supplied peer labels. Join current slot, worker selection, grant, source version and cancellation records. CheckLaunchCredentials must read the protected held record before first BindLaunch, preserving existing plan, grant, event and permit checks. Current source revocation blocks new opening. |
| lb-v2-lifecycle | Keep the fix-9 Prepare and launch order. The retained helper_prepare effect now waits for the projection receipt; persist/reconcile it under the same causal operation before the existing identity commit and OpenGate. Every error after Acquire or Inject must fence and withdraw the original projection, then use existing real quiescence release. No second Acquire or fresh home on ambiguous restart. The transfer is helper-internal; lifecycle and service never copy descriptor bytes. |
| lb-v2-integrate assembly | Pass ProjectionIdentity to secrets, configure both narrow ports through RuntimeServices and install the deferred projection launcher into every launcher consumer. Construction and Probe do not invoke BindCredentialProjection. Every Prepare and Launch requires completed runtime configuration and all clients. Only the explicit empty-authority materialize worker may skip binding at Prepare; unknown or other shapes require it. Every Launch, including recovery, binds because PreparedLaunch carries no trusted spec. Preserve the exact owner error and retry only certified unbound failures. The shipped stub does not block health/enrollment startup and keeps these launches closed. |

credential-controls.json adds forty-four named deciding controls to the existing
runner inventory. They weaken actual selected-source, native descriptor,
destination identity, held proof, gate fence/permit or cleanup predicates and
nominate reached TestProjection tests and assertion diagnostics. The catalog
retains every prior row. Each control must compile under ordinary Linux, faults,
Darwin and both dedicated-authenticator variants, fail its named assertion on
Linux and pass the same candidate assertion. Syntax or compile failure is setup
failure; static success establishes no runtime red. The tests' real unlinked
synthetic descriptors and input-sensitive observation fixtures prove no actual
native peer or installed credential delivery. Consumer acceptance still needs
a native descriptor canary with a control, interrupted acknowledgement/restart,
source revocation racing OpenGate, actual zero-count withdrawal and protected
canonical refresh behavior. No real credential or AI-service request is part
of this contract-authoring phase.

#### Prepare/open policy fence and turn event identity

The store owns a fresh policy fence at helper_prepare and helper_open, outside
lifecycle's earlier plan construction. PolicyStore embeds CurrentPolicySource:
CurrentApprovedPolicy(ctx, Scope) returns the approved head from the actual
locked store snapshot, ignoring a historical Scope.PolicyGeneration selector.
Its owning store stub returns lb-v2-service not_implemented until implemented.
BindCurrentLaunchPolicy reads that port and binds a private transaction fence
to the current generation, configuration, helper kind and effect. The field is
unexported and cannot arrive in a serialized transaction. ValidateTransactionShape
requires it for agent prepare/open writes and requires every retained
record.Reservation.PolicyGeneration to equal that approved generation. Missing
stamps, a prepare stamp reused for open and a foreign effect refuse. The existing
prepare validator still owns the required retained-plan and identity binding;
workers retain their separate leased-job authority.

The single store writer invokes BindCurrentLaunchPolicy inside the same writer
critical section as validation and commit. The helper-open authorization and
service Open source must make this fresh check immediately before releasing
the native gate; checking a completion after exec is too late. A D6 change after
sealing the plan therefore refuses its old generation at prepare or open. Keep
the original failed receipt, reconcile/abort the unopened gate and reserve fresh
authorized work; do not edit the sealed digest. Historical authentication and
exact replay for a process that already opened retain fix 11's existing rules.
The code gate is exercised by TestGatePolicy with a mutable approved-head source,
an unchanged historical scope, both helper kinds, absent/reused stamps and a
preserved source error. This is a contract check; the native store/helper owners
must still implement the locked read and actual pre-exec ordering.

Every new lane.turn event must carry a nonempty valid logical_turn_id in the
Event envelope. This applies to public lifecycle writes, helper_open,
mail_deliver and every other permitted emitter, with no emitter exception.
ValidateTransactionShape enforces this common envelope requirement. Producers
copy the real TurnSnapshot.LogicalTurnID for that life/run; they never infer one
from an operation ID or leave it to a reader. Other events keep the existing
optional envelope field; the TurnEvent payload map is unchanged. TestTurnEvent
and separate public/open/mail controls exercise the same deciding validator.

These two narrow additions add eight controls to credential-controls.json. The
inventory at that point is 218 Go controls and four other rows, for 222 runtime rows.
The original 44 credential controls and every prior row remain active.

#### Review corrections: final environment and startup boundary

The post-isolation envp rule in section 6 and the task-environment row is
mandatory, including for the selected headless token. CredentialExecEnvironment
records names only, the prepared identity, final vendor stage, actual lane UID
and GID, measured zero remaining capabilities and completed boundary setup.
ValidateCredentialEnvironment rejects an earlier stage, root or foreign UID,
unknown/nonzero capabilities, incomplete isolation, a selected name in an
earlier process environment, or an absent/duplicate final name. The helper
invokes this contract gate immediately before execve using actual native facts;
serialized labels are not producer evidence and no raw values enter this DTO.
As defense in depth, credentialEnvironment also refuses the glibc secure-exec
names GLIBC_TUNABLES, GCONV_PATH, GETCONF_DIR, HOSTALIASES, LOCALDOMAIN, LOCPATH,
NIS_PATH, NLSPATH, RESOLV_HOST_CONF, RES_OPTIONS, TZDIR and IFS, plus MALLOC_
prefixes. These refusals do not weaken the final-only placement requirement.

Environment holding permits a root-owned anonymous object with Links zero or
a root-private buffer object with Links one, private 0600 mode and 0700 parent.
Neither has a lane-visible filename or alias. File targets still require Links
one and their exact file ownership/read-only projection rules. TestEnvAnonymous
covers the zero-link success and foreign-owner refusal; sources remain unlinked
and separate from these helper-held destinations.

Assembly's projectionLauncher is installed before dataworker/lifecycle launcher
consumers are constructed. Runtime binding stores its clients without calling
the native binder. The first projection-bearing Prepare or recovery Launch
calls the binder, retains successful or uncertain/permanent results, and
returns a refusal before the underlying operation. Only the certified unbound
transient failure below permits another attempt. Probe and the explicit
credential-free materialization Prepare remain independent of it. This is deferred
binding, not swallowing a binder error. TestProjectionStartup and
TestProjectionPrepare exercise the production runtime-binding boundary with
the shipped admin binder stub, tracked actual calls, healthy port dispatch and
enrollment dispatch before and after a refused Prepare. TestProjectionWiring
checks the actual assembly source does not move that call back to construction.
The fixture host is an input-sensitive component model, not a native listener
or signed enrollment. Installed serve still needs the other owning components;
no component fixture is reported as an installed serve E2E pass.

The native follow-up NATIVE-TASK-ENVP-1 must observe the privileged helper,
bootstrap, boundary program and outer-launcher environments and the final
child's envp with an ordinary random canary. It must show the selected canary
only in the final unprivileged child, with actual UID/capability/isolation facts,
and a control that applies it early must fail. Keep values private; retain only
names, hashes of the ordinary canary if needed and verdicts. No credentials,
environment dump, model request or such native run is authorized on this Mac.

Nineteen review controls now cover the secure-execution names, six final-exec
predicates, anonymous environment holding, deferred binder refusal and actual
assembly wiring, the three shared lease-state consumers and the closed state
vocabulary. Mail delivery also rejects the old running effect label; both
runner planners use EffectClaimed. That revision has 71 credential controls, 237 Go
controls and four non-Go controls, for 241 runtime rows. Runtime red/candidate
assertions are pending the authorized Linux run; static compilation is not a
reached assertion or native containment proof.

#### Fix 12d: delta review corrections

Codex's retained HelperAllocate record must have State EffectCompleted while
its EffectOutcome.Status remains succeeded. The planning lease still requires
EffectClaimed. The closed vocabulary applies in product code and in fixtures;
TestAllocState requires a real Start plan from a completed allocation.

projectionRequired is fail-closed. Its sole credential-free Prepare exception
is Kind worker, a nonnil materialize WorkerPlan, no Runner/Capture/PlanID, no
resource, data, secret, profile, network or channel grants and no injection selectors,
versions, outcome or target. All other and unknown shapes require binding.
Both Prepare and Launch check completed runtime configuration and nonnil binder,
broker and identity before delegation. Configuration becomes ready only after
host BindRuntime succeeds. Every Launch binds, including restart recovery and
materialization Launch, because PreparedLaunch alone proves no free shape.

Binding has one successful use, serialized across Prepare and Launch. A failed
attempt may retry only when the authenticated owning binder returns the private
CredentialBindingFailure with Unbound true and an lb-v2-admin Error whose Code
is unavailable and Retryable is true. Unbound certifies that the owner has
verified no client was installed and no partial bind remains. A flag copied
from a caller is not this producer observation. Generic retryable errors,
partial/uncertain binds, missing causes, foreign owners and permanent errors
remain cached and fenced; there is no reset or second successful binding.
The original cause remains available through Unwrap, including owner and
recovery instructions. TestBindRetry proves a certified failure can retry
without restarting; TestBindRetryFence and TestBindFailure exercise the stopped
cases and the one-success rule. The shipped not_implemented stub remains a
permanent refusal and is called only once.

ValidateCredentialEnvironment now requires the complete validated holding
receipt, valid authority and held-record generations, matching unrevoked
source inventory, and nonzero matching UID and GID. ObservedAt is the actual
native final-exec observation time; the helper derives CredentialTargets again
at that time and requires exact authority equality. This covers the headless
slot, selected lane env grants and protected worker credentials. Each injected
task-secret name and every nonfixed Runner.EnvironmentNames entry must resolve
to the selected allowed environment target. Selected names must occur once in
the final envp and nowhere in earlier processes. Empty/truncated targets cannot
turn the check into an empty successful loop.

The pinned adapters' fixed HOME/PATH/TMPDIR/XDG directory names and their
driver-specific CODEX_HOME or Claudock configuration/registry names remain
helper-derived settings, never granted task values. credentialFixedEnvironment
recognizes those exact per-driver names; every other runner name requires a
selected target. CLAUDE_CODE_OAUTH_TOKEN always requires its selected headless
slot. TestEnvModes covers both that slot and worker credentials; TestEnvFixedNames
checks the fixed-name distinction without allowing another driver's settings.

credentialEnvironment additionally refuses GIT_, PERL, RUBY, JAVA_ and JDK_
prefixes and PROMPT_COMMAND, CDPATH, PS4 and GOFLAGS. File destinations still
require one link, including the headless token. TestEnvAnonymous's slot/task
subtests and TestEnvFile refuse zero-link file substitution. TestSharedLease now
also reaches ValidateWorkerPrincipal, so all four api claimed-state consumers
share the same positive lease-state value.

The 65 new deciding controls bring credential-controls.json to 136 controls,
the Go inventory to 302 and all runtime rows to 306. They preserve all previous
rows, adjusting only the two binder anchors to the shared deferred gate.
New nominated test paths, including subtests, are under 40 characters. Static
vet proves compilation only. Reached-red, intended-diagnostic and candidate-pass and
native/installed-service evidence remain supervisor Linux/owner work.

### Draft.4 fix 13: org, attestation and scheduler decisions

This section resolves the three cited owner requests. It freezes shared
semantics and private inputs; it does not report an installed validation,
hardware enrollment, scheduler dispatch or native cleanup result.

#### Q1. Canonical org inventory and exact snapshot selection

ResourceFile.Kind has a context-specific closed vocabulary:

| Collection | Canonical Kind | Meaning |
| --- | --- | --- |
| OrgSnapshot.Sources | prompt, drivers, policy, source, task | Semantic source document type. The L5 prompt and driver records keep prompt and drivers. |
| OrgSnapshot.Derived | file | Generated regular-file output. A derived output never substitutes for a semantic source. |
| Source/ownership manifest tree entries | file | Filesystem entry classification; this is distinct from ResourceFile.Kind in Sources. |

ValidateOrgKinds checks the generation supplied in snapshot.Ref.Generation.
It must be a nonzero generation within the shared integer range, and Sources
must be nonempty. Generation 1 requires an explicit non-nil empty Derived
array; nil and nonempty Derived both refuse. Generations greater than 1 require
nonempty Derived, with Kind file on every entry. The two generation branches
are exclusive. No derived entry substitutes for a semantic source, and file
is never an alternate Sources spelling.

Templates calls this same gate from ValidateInitialSources and checkSnapshot;
admin's validateInitial calls ValidateInitialSources and retains its exact
L5 prompt and driver pins. The initial source importer requires generation 1
and delegates the nonempty Sources and initial Derived shape to the shared
gate; it does not pre-check or shadow them. Later approved snapshots require
validated regular-file outputs through the other generation branch. Full template
validation retains inventory, path, mode, digest, revision, renderer,
ownership, source read-back, role pairing and content checks. Source and
ownership tree entries still use the independent filesystem kind file.

OrgSnapshotRequest is an exact expected-head lookup in Scope.Config.
OrgID must equal ID(Scope.Config), and Generation must be nonzero and within
the shared integer range. Either omitted selector is invalid_request; omission
never requests current. A valid request whose generation differs from the
current approved publication returns conflict, including an old or future
generation. No stale history or alternate org is returned. A stored projection
with another configuration or org identity is integrity failure. Authorization
still comes from the authentic scope and protected store, not its config label.

The store owner must implement these selector and projection checks on its
authorized current-head lookup. At this HEAD, store.OrgSnapshot in
internal/v2/store/contract_stubs.go returns an owner-named NotImplemented;
the shared validation gates do not turn that pending port into an implementation.
Templates OrgValidate passes OrgID ID(scope.Config) and request.Generation;
resolveApproved takes OrgID from Scope.Config and the expected generation
from provided.Snapshot. checkSnapshot requires the returned OrgID to equal
ID(Scope.Config), including OrgValidate, BriefRender and BriefStart. Existing
reference, context and read-back comparisons remain.
ValidateOrgSnapshotRequest and
ValidateOrgSnapshotSelection express the shared selection gate. No field in
ResourceFile, OrgSnapshotRequest or public OrgValidateRequest changes.

Bootstrap performs no OrgSnapshot read. Its existing private AuthorizationTarget
port supplies the current org baseline; bootstrap requires BaseGeneration zero,
and the single writer must enforce the absent-org Compare at publication. A nonzero
baseline conflicts, and target lookup errors propagate without a snapshot
fallback. The native store must derive that baseline from actual protected
state and enforce the atomic comparison; a serialized target is not authority.

| Owner | Required coordinated change |
| --- | --- |
| lb-v2-templates | Keep the shared kind gate in initial and full validation, preserve every other gate, and retain exact selectors at both named calls. |
| lb-v2-admin | Keep semantic initial inventory and exact L5 source pins; keep tree-entry file checks separate. |
| lb-v2-service/store | Implement the pending exact selector, current-head and projection checks; derive the bootstrap baseline from protected state and enforce its absent-org CAS. |
| lb-v2-serve2 | Retain the semantic initial fixture and exercise that same publication through installed org.validate after the coordinated changes. No harness-only kind conversion is allowed. |

#### Q2. Protected installation attestation policy

InstalledAttestationPolicy is the administrator-owned record with schema
laneboss.attestation-trust.v2, Config, InstallationGeneration, RootsDER and
optional AllowedAAGUIDs. JSON uses schema, config, installation_generation,
roots_der and allowed_aaguids. Each roots_der element is the standard JSON
base64 encoding of one complete DER public X.509 CA certificate. A private
key, PEM concatenation, root name, URL or registration x5c chain is not a pin.

ValidateInstalledAttestationPolicy requires exact configuration and installation
generation, at most 32 roots, at most 65,536 bytes per root and at most 512 KiB
of total DER. Each certificate must parse and have valid CA basic constraints,
IsCA and certificate-signing key usage. A root must have identical raw issuer
and subject and verify its own signature. Subordinate CAs and duplicate DER
or public-key pins refuse, including a reissued certificate for the same key. At most
256 distinct canonical lower-case AAGUID strings may narrow this trust. An
empty allowlist imposes no model restriction. Zero roots is an explicit closed
registration policy, with no nonempty allowlist; it supplies no default trust.
Certificate validity at ceremony time and chain/statement verification remain
identity's actual service-clock checks.

The operator can pin both Yubico's U2F root and Yubico Attestation Root 1 by
placing their exact, independently verified public DER certificates in the
same RootsDER array. Neither is built in, fetched, trusted by subject name or
taken from OS roots. The protected operator input supplies the bytes. An
allowlist for fido-u2f must include the all-zero AAGUID when an allowlist is
used; that value does not identify a U2F model. Root issuance policy, UP, UV,
RP, origin, nonce, signatures and every existing format check stay mandatory.
Touch alone or an unconfigured PIN cannot be reclassified as UV.

Admin install owns the new protected boot member attestation_trust containing
this record. It is an inline member of the root-owned service installation
document, not a public AdminInstallRequest or registration parameter. Admin
validates the record before atomic publication. The installation document and
all ancestors must have the existing protected ownership, regular-file and
no-shared-write checks; service and lane processes cannot replace this policy.
No environment override, new public RPC, CLI default root or network metadata
lookup is introduced.

Identity 9ffbd01 is present, including Dependencies.Attestation. Assembly's
next coordinated change adds Installation.AttestationTrust with that JSON member. It reads the same protected
boot bytes once, validates against installed.Config and the protected binding's
InstallationGeneration, and also requires an installed AdminEnrollment endpoint
to name that same generation when enrollment is enabled. It deep-copies the
record using CloneInstalledAttestationPolicy and maps Config,
InstallationGeneration, RootsDER and AllowedAAGUIDs exactly into the existing
identity.AttestationPolicy constructor input at
identity.Dependencies.Attestation. Identity freezes another private snapshot.
Both an absent attestation_trust member and a present policy with zero roots
mean closed production registration. Absence is retained in the protected
installation document for that generation's audit; a present closed policy
retains its explicit policy bytes. Neither spelling supplies trust. Malformed or
mismatched supplied policy refuses rather than becoming absent. Ordinary
service construction and existing non-enrollment operations need no invented
root. The identity constructor field is present; assembly's protected-policy
mapping remains the next coordinated change and is not yet an installed wire.

Policy bytes are immutable within one installation generation. Rotation
publishes a coherent new protected installation generation and bindings, retires
old outstanding enrollment challenges, and reconstructs identity. Keep the old
policy bytes for ceremony audit. Every new ceremony must use the policy matching
its exact Config and InstallationGeneration. Rotation changes new enrollment
trust; it does not silently upgrade or reclassify historical credentials.
Previously enrolled credentials retain their recorded provenance and current
enrollment revocation checks. Removal intended to distrust existing credentials
requires explicit authorized revocation of those credential IDs; it is not
implemented by pretending their historical attestation used the new roots.
No online CRL, OCSP or metadata revocation check is implied.

| Owner | Required coordinated change |
| --- | --- |
| lb-v2-admin | Add the protected attestation_trust installation input, validate and publish exact public DER pins and optional allowlist, and own coherent rotation/challenge retirement. The browser producer requests direct attestation and required UV. |
| lb-v2-integrate assembly | Wire the present identity constructor field: validate and clone the protected record and pass its four policy fields into Dependencies.Attestation. Add installed missing/mismatched-policy controls; do not merge owner branches in this lane. |
| lb-v2-identity | Consume the constructor policy with its certificate-backed packed/U2F implementation, preserving no-root refusal, actual signature and chain checks and simulated-presence separation. |
| lb-v2-service/store | Implement real ReserveEnrollment and EnrollmentChallenge and bind their current installation generation to the ceremony. Retain original evidence and one-use semantics. |
| lb-v2-serve2 and operator | Drive the installed real-key ceremony only after these owners land, pin the chosen public roots and retain actual UV/attestation results. The owner performs the final hardware enrollment. |

#### Q3. Private automatic loop reservation

ReserveLaunch keeps its existing signature and gains one necessary private
request alternative: LaunchReservationRequest.Loop *LoopTurnSelector.
OperationID, ContinuationID and Guards must be empty on that branch. The manual
original-frame path and same-logical-turn profile continuation remain unchanged.
An automatic loop is not a continuation and never fabricates a public lane.turn
frame, lane actor, ticket, proof or prior configurator scope.

The installed scheduler has Actor Kind scheduler, its actual installed ID and
no lane life, level or role. SchedulerIdentitySource.VerifyScheduler is a
non-serializable installed service dependency. Its native owner authenticates
the actual private caller, installed capability ID/revision, configuration,
installation generation, boot, current policy permission, expiry and lifetime.
BindSchedulerScope validates that producer's InstalledScheduler and keeps a
private non-JSON scope binding. A copied JSON scope, actor string, service
label or watchdog label cannot fill it. CheckSchedulerScope calls the same
producer again before reservation and replay; changed or revoked authority
refuses. The service/store supplies its locked current capability/policy view,
with native lifetime checked before entering and again before committing the
short writer transaction. Structural validators are not native authentication.
InstalledScheduler.ExpiresAt is the fixed expiry of the current
CapabilityGeneration; a renewed lifetime requires a new CapabilityGeneration.
The private scope has no connection, frame, request, launch, endpoint generation,
read view, read authority or public source label. Its bound scheduler must
satisfy the complete InstalledScheduler shape even before the native recheck.

LoopTurnSelector contains only Target, SettingEventID, SettingSeq,
SettingOperationID, EndEventID, EndSeq, ExpectedGeneration, CancellationEpoch
and PreviousLaunchID. These select the exact enabled durable setting and
causing end; they cannot supply new text, a role, grant, budget or launch ID.
Selector.Target is the causing run's LifeRef.
The setting persists across runs and its target run may precede the causing
run of the same life. The writer resolves the original configurator and actual
event payload from protected state, rather than believing these IDs alone.
The setting may be enabled or amended after that run has ended. Its event and
the end event must be distinct; their sequence order grants no authority.

The same writer rechecks the installed scheduler capability, latest enabled
setting, current idle/verifying uncleaned life, expected generation, epoch,
previous launch, current policy and grants, budget, driver/model/profile
eligibility and retained history. Require the exact committed terminal end,
known zero survivors and no later running/lost observation. DueAt is exactly
End.Observation.ObservedAt plus Setting.BackoffMS milliseconds; compare it
against the trusted clock, and refuse an early call.
Consume a unique key for configuration, life, causing run and end event, also
fenced against a manual launch. Disabling the loop, revocation, cancellation,
policy change or another launch wins the corresponding atomic comparison.
A retry reauthorizes the caller and returns the same retained reservation;
it creates no second operation, event, input, grant, slot or logical turn.

LoopTurnCause is the canonical immutable manifest for this branch. Its exact
field map is the Go definition in api/loop_turn.go: schema, verified scheduler,
selector, ConfiguredBy, full LoopRequest setting, full RunEndEvent,
GrantGeneration, PreviousSession, PreviousHome, BudgetRemaining, DueAt,
ReservedAt and store-issued reservation, operation, causal request, launch,
grant-set, new and previous logical-turn and PlanLaunch-effect IDs.
The setting's idle task ref binds exact retained bytes and byte count.
BudgetRemaining must match the end and current remaining counters; no reset
or paid fallback is allowed. The new logical turn must differ from the old one.
Mail still uses ordinary protected turn selection and delivery; reserving a
loop never acknowledges mail.
The configurator is a complete human actor with no lane fields, or a complete
lane actor with life, level 3 through 6 and role. The end observation has a
process handle ID. Retained session vendor version is required, and a causing
run after run 1 also requires its vendor conversation ID. The home pins a
distinct root and workspace, history and a clean relative vendor directory.
New store-issued IDs are distinct from one another and from the selected end,
setting event, setting operation and previous launch identities.

The second necessary private change is LaunchReservation.Loop *LoopTurnCause.
For this branch Mode is turn, RequestedBy is the actual scheduler, and
Authority is scheduler plus its installed CapabilityID. Target.Run is causing
run plus one, Generation is expected life generation plus one, and ancestry,
role/level, driver and all existing grant/spec pins remain. OriginalRequest is
the private manifest of canonical LoopTurnCause bytes, with exact byte count
and SHA-256 also in RequestSHA256. RequestID is a store-issued causal identity,
not an authenticated public frame. Plan and runner consumers must branch on
Loop to read that manifest and compare it to the reservation; treating those
bytes as a public Request is forbidden. Existing manual bytes are unchanged.
Launch inputs keep the cause's exact GrantGeneration. The plan keeps its exact
remaining budget, home root and complete Home, a nondecreasing home generation,
session ID, history, home ID and any retained vendor conversation ID. Every
planning, prepare and open write keeps LogicalTurnID, the planning write keeps
PlanEffectID, and the bound lane projection keeps that same LogicalTurnID.

The writer commits that manifest, pending operation/receipt, reserved plan,
fresh current grant snapshot, causal-end claim and one ordinary PlanLaunch
outbox effect together. The effect retains the actual service executor and
the scheduler as RequestedBy, with the new logical turn. No generic service
principal acquires scheduler permission from that outbox effect.

A new loop.reserved event carries the complete LoopTurnCause and the exact
scheduler actor/requester, operation/request, target and logical-turn envelope.
Only the dedicated ReserveLaunch writer branch emits it; ordinary public
transactions and the generic launch_plan row cannot append it.
loop.reserved is private human/service metadata like launch.planned; the
lane-visible audit is lane.turn with Trigger.Kind loop. On opening,
the existing lane.turn event is the loop launch audit: actor and requester are
the scheduler, Trigger.Kind is loop, CausingSeqs contains setting then end
sequence, and Task is the exact idle input. Prompt still names actual retained
rendered bytes. ValidateLoopReservedEvent and ValidateLoopTurnEvent check
these pins. An opened loop plan requires exactly one such lane.turn through
the shared transaction preflight. Helper/identity events keep their actual
executor actor and scheduler RequestedBy; the configurator remains separate.
The trigger spelling loop replaces the former idle spelling in the closed
Trigger.kind catalog. Both mail ID arrays are empty; CausingRun equals
Selector.Target.Run. Omission or zero refuses. The event prompt equals the retained plan's
Runner.Prompt. Any lane.turn carrying a scheduler actor, scheduler requester
or loop trigger must match an opened loop plan in the same transaction,
including public, manual helper-open and otherwise empty transactions.

| Owner | Required coordinated change |
| --- | --- |
| lb-v2-identity, native service and admin | Authenticate the installed private scheduler capability and implement SchedulerIdentitySource against actual protected installation/native lifetime facts. |
| lb-v2-integrate assembly | Bind that one producer through BindSchedulerScope; no actor-label-only scheduler path is installed. |
| lb-v2-service/store | Implement the Loop branch of ReserveLaunch on the same single writer with all current fences, unique causal-end claim, canonical input, pending reply, event and PlanLaunch outbox. Recheck CheckSchedulerScope before replay/commit. |
| lb-v2-lifecycle | Treat LoopDue as a read, select exact setting/end IDs, call the private loop alternative, and preserve actual scheduler cause and new logical turn through planning/opening. |
| templates and both runner owners | Read canonical loop input on the private branch and retain exact task, prompt, session, history and budget; keep the manual original-frame path unchanged. |
| lb-v2-serve2 | Require due/replay/race/restart, disabled/revoked/stale, policy/epoch, nonquiescent, early and exhausted-budget installed controls before crediting automatic dispatch. |

#### Q3. Atomic failed-plan cleanup writer

The lifecycle-local port at 87f5dad,
`internal/v2/lifecycle/plan_fail.go:15-43`, is promoted without changing its
field layout to api.PlanCleanup and api.FailedPlanStore:

```go
FailPlan(context.Context, api.Transaction, []api.PlanCleanup) (api.Commit, error)
PlanCleanup(context.Context, api.Scope, api.ID) (api.PlanCleanup, error)
```

Lifecycle adopts type aliases to these shared types, eliminating the store's
need to import a lifecycle-owned type. PlanCleanup retains ID, Kind, Cause,
ReservationID, LaunchID, Slot, SlotResult, SlotKnown, Injection, InjectionIn,
InjectionOut, Prepared, Withdrawal and Issues. Kind is exactly withdraw,
release or revoke_injection. These are private outbox requests, not receipts.

FailPlan requires one failed LaunchPlan revision under InternalLaunchPlan,
its existing plan CAS and cancellation guard, original operation/requester
and real planning claim. ValidateFailedPlanWrite is the shared correlation
preflight. Under the same writer lock the store independently resolves that
live original claim, immutable reservation, actual stage refs and original
prepared/projection selector. Commit the failed plan and every cleanup request
in one transaction or neither. A separate enqueue after Transact is forbidden.
Once HelperAllocate is claimed, a failed revision commits only through
FailPlan. The structural preflight conservatively rejects every failed
InternalLaunchPlan revision in ordinary Transact and validLaunchPlanWrite;
only ValidateFailedPlanWrite validates it together with a nonempty cleanup
batch. When no credential-slot stage exists, record the original error as
effect and operation failure and keep the plan's last committed phase; do not
fabricate a failed plan revision or cleanup batch. No grants, worker leases or ordinary planning
effects may accompany the failed revision; its only event kinds are
launch.planned and capture.refused.
Keep stage bytes immutable and make exact retries return the original commit
and identical jobs, with a unique cleanup identity for each reservation/kind.
Changed retry bytes or selectors conflict.
Cleanup cause IDs are pairwise distinct and differ from the planner's cause ID;
cleanup effect IDs are pairwise distinct and differ from the planner's effect ID.
A loop cleanup keeps the loop's LogicalTurnID.
Known slots require slot, profile grant, profile, lease and expiry fields;
when a plan is retained, the slot and any injection equal its exact resources.
Prepared cleanup requires its own prepared ID, containment, endpoint generation,
gate and process generation, the retained handoff digest and the plan lease's
containment and endpoint generation. Unknown fields remain reconciliation
issues; they cannot contradict resources already retained in the plan.

A confirmed unprojected allocation requires both release and revoke_injection.
A bound or uncertain projection requires only withdraw first. Unknown
slot/injection/projection outcomes remain explicit Issues with owner errors
and original stage refs; they are never empty resources or measured zero.
The outbox reconciles the original projection, obtains the broker fence, calls
helper WithdrawCredentials and verifies FinishCredentialWithdrawal before
Release/RevokeInjection using actual helper quiescence. Lookup unavailability
is not absence. No failed-write error, policy drift or uncertain collection
authorizes fresh opening or allocation reuse.

No new member is added to Effect, no cleanup work is hidden inside PlanLaunch
or Worker and no helper abort/release is granted to the launch_plan row.
The service-owned cleanup outbox is a specific capability of this atomic
private port. Its dispatcher retains measured completion evidence and does not
complete/delete a request on a mere successful enqueue. Shared type validation,
map fixtures and interface availability are not native cleanup acceptance.

| Owner | Required coordinated change |
| --- | --- |
| lb-v2-lifecycle | Alias PlanCleanup and FailedPlanStore to api, call ValidateFailedPlanWrite before the existing atomic port, retain original error and allocation on failure and read back exact failed plan/jobs. |
| lb-v2-service/store | Implement FailPlan and PlanCleanup on the existing single durable writer/outbox with actual claim/fence checks, atomic failure rollback, exact replay and retained job completion. |
| lb-v2-secrets and lb-v2-admin | Consume original protected selectors and perform fenced withdrawal and measured quiescence before real slot release or injection revocation. |
| lb-v2-serve2 | Measure rollback, lost-reply/restart, uncertain projection and cleanup ordering on the installed owners; no allocation collection is credited from the lifecycle fixture. |

The frozen public request DTOs, human credential/enrollment DTOs and Effect
union remain unchanged. This round adds the protected attestation record,
scheduler private types/binding, two private Loop pointer fields and the
loop.reserved event payload/loop trigger semantics because those questions
require them. Owner constructors, validators and durable/native implementations
must adopt these decisions together; no new runtime success is inferred here.

The contract-controls.json manifest has 184 deciding controls: thirty-eight org kind
and exact-selection rows, twenty attestation policy, clone and closed-state rows,
ninety-seven scheduler, loop plan and audit rows and twenty-nine failed-plan
cleanup rows. Fix 13c added 93; fix 13d removes the obsolete empty-Derived
refusal control and adds twelve controls for empty inventories, consumer
consistency, exact selectors and mandatory causing run.
Fix 13e adds seventeen controls for generation-selected Derived shapes,
single-gate delegation, org configuration fences and bootstrap absence/CAS.
The inventory is now 486 Go controls and four non-Go rows, for 490
runtime rows. Each new test path is under 40 characters. Linux must establish
the named reached failure with its intended diagnostic, followed by the same
candidate test passing; static compilation establishes neither result.

#### G11. Authorized lane collection and retained receipts

The private contract in api/collection.go and api/collection_proof.go covers
cleanup of an archived merged or abandoned lane. PlanCleanup, FailedPlanStore
and all Q3 failed-launch rules remain unchanged. A released process lease is
only a prerequisite: it does not remove objects, a worktree or a branch and
cannot set Lane.Cleaned. No public request DTO, Effect union member or
CleanEvent field is added. CleanEvent keeps its existing removed/retained ID
lists; the successful original effect's Output names the full retained receipt.

CleanupIntent has a stable store-issued ID, the original InternalLifecycleEffect
cause, expected lane generation, terminal decision, verified ArchiveReceipt
and original ArchiveRequest, helper ReleaseReceipt and protected CleanupWorkspace.
The cause carries configuration, exact life/run, original operation/request,
actual service executor, original human/lane requester, effect ID and
cancellation epoch. CleanupJob pairs that intent with the current original
EffectLease. ValidateCleanupJob requires a live claimed Clean effect, no
outcome or competing effect payload, exact cause/request/target/generation
joins, verified archive bytes and original archive run, and genuine-shaped
release/quiescence records with known zero survivors, connections, jobs and
writable exports. Shape checks never authenticate a caller or infer current
authority from labels. The writer resolves these records from protected state.

The optional CleanupObjectStore extension is chosen because the existing
single service writer owns blob reachability and retention. Its BeginCleanup
resolves the original live effect and persists/replays the stable intent.
CleanupInventory snapshots the complete bounded ownership/reference graph;
CollectCleanupObjects performs authorized object operations;
RetainCleanupReceipt retains exact receipt bytes; CleanupReceipt reads them;
CompleteCleanup atomically publishes verified completion. Scope is an
authenticated service capability; a worker label cannot acquire deletion.
CleanupDataWorker.CollectCleanup is the grants-owned orchestration extension.
Existing ObjectStore, StateStore and DataWorker implementers are not silently
given these capabilities. Missing installed support returns an owner-named
not_implemented or unavailable error and leaves cleanup pending/refused.
No alternate deletion route follows an authority refusal.

CleanupInventory pins its own ID, intent, configuration, target, expected
generation, cancellation epoch and protected graph generation. Each
CleanupObject binds its BlobRef and exact content hash/length, opaque root,
protected parent/object identities, owner life, ownership generation, role and
reference count. Entries are unique and complete. Installation count budgets
have a 4096-entry floor and otherwise derive from approved memory/disk budgets
or protected installation settings. Immutable manifest byte bounds still apply;
a bounded refusal never truncates the inventory.
Known owners require a positive ownership generation. An empty owner may have
generation zero when no ownership record exists; retain it as unknown without
inventing an ownership generation. Nonzero generations remain bounded.
An oversized graph requires owner reconciliation, never truncation. The
archive manifest is mandatory. The service must enumerate from actual owned
storage and retained references, not a caller's proposed list or a pathname
walk chosen by a worker. Keep events, inputs, captures, reports, archive and
history references. Unknown ownership/role, foreign ownership and live
references require retention. Only an owned, unreferenced transient artifact
may be removed. The graph fence prevents new references or substitutions
through collection and the final commit.

Every ObjectDisposition names the inventory object in inventory order, its
remove/retain decision and exact reason, with protected before/after read-backs.
Before must identify present exact bytes and the original object identity.
Removal requires actual absence in the original protected parent namespace;
retention requires present exact bytes and identity. Read-backs have distinct
observation IDs and ordered timestamps after archive verification. Missing,
duplicate, substituted, corrupt or unreadable entries refuse. Both inventory
and receipt manifests bind the exact bytes returned by CleanupInventoryBytes
or CleanupReceiptBytes: set the record's Manifest to zero, then use the
existing canonical JSON encoder. Hash and byte count refer to that body;
the returned manifest BlobRef names the retained body. These helpers perform
no I/O. The native store must retain and reopen those exact bytes durably.
The receipt manifest ID must differ from the inventory manifest ID as well as
every inventory object ID; retaining one record cannot overwrite the other.
The inventory manifest, receipt, completion evidence and audit records are
themselves retained roots, outside the deletable snapshot.

CleanupWorkspace carries opaque workspace, root and repository IDs, exact
target, workspace generation, protected parent/directory/Git identities, fixed
lane/<life> branch and pinned Git head. The administrator resolves these in
its protected registry; Workspace strings never become deletion paths.
WorkspaceCollector.InspectCleanupWorkspace reads real worktree status and
branch identity. RemoveCleanupWorkspace rechecks the original claim and
protected handles, performs unforced worktree/branch removal only after a
known clean decision, syncs its durable journal and reopens both namespaces
to observe absence. WorkspaceRemoval includes the intent/claim, action,
before/after observations and unforced/synced evidence. Dirty work yields
retain_dirty with both directory and branch preserved, unchanged head and
known dirty status. Unknown status, changed Git/head/parent identities,
forced removal, missing branch/worktree read-back or unavailable reads refuse.
Dirty retention and unknown ownership cannot complete Lane.Cleaned. An
abandoned branch with commits that unforced Git removal refuses remains
pending; this contract grants no force flag or manual fallback authority.

CleanupReadbacks is an installed private service/administrator dependency,
never a public setter or client-supplied receipt checker. CheckCleanup must
authenticate the native caller and resolve the original current effect claim,
lane generation/epoch, terminal decision, archive, release, protected workspace
and complete reference graph both before and after reads. ReadCleanupInventory
and ReadCleanupReceipt reopen retained bytes. ReadCleanupObjectResult and
ReadWorkspaceRemoval read authenticated operation journals, including the
actual protected before observations and unforced operation facts.
ReadCleanupObject and ReadCleanupWorkspace independently reopen the current
namespace, content and Git state. Echoing a proposed receipt, treating lookup
failure as absence or using an in-memory receipt as a native journal violates
this port. Keep protected identity/reference fences through the final CAS.

VerifyCleanup validates those retained records, every object journal and
fresh content/absence read, administrator journal and fresh worktree/branch
read, then rechecks current authority, context cancellation and lease expiry.
Fresh observation IDs differ from all journal IDs and each other, including
the workspace observation. Equal timestamps do not permit an echoed journal.
Every measured timestamp must precede or equal CheckedAt; both verification
and completion reject a clock that moves behind the measured observations.
Integrity failures name lb-v2-service for inventory, receipt and object reads,
and lb-v2-admin for workspace journals and worktree/branch reads.
Only that path creates VerifiedCleanup, whose private fields bind job,
inventory, receipt and independent proof digests. Accessors return copies.
A serialized receipt or zero verification value cannot replace these reads;
restart/reclaim must reauthorize and repeat them. Validators are component
preflights, not native implementations or proof that an installed port is honest.

CompleteCleanup holds the service writer's current authorization, graph and
cancellation fences while calling ValidateCleanupCompletion. Commit retained
receipt and fresh evidence, exact lane generation increment/Cleaned flag,
original successful effect outcome, original operation/reply and lane.cleaned
event together or none. The event retains actual service Actor and original
RequestedBy, operation/request and life/run; its archive, quiescence and every
removed/retained ID match the measured receipt. No competing effect outcome
payload is allowed. Cancellation, revocation, another generation/claim or
reference change wins the comparison and prevents success.

Use an idempotent protected deletion journal keyed by stable intent/object;
after a crash, absence without the original authenticated before/operation
journal is uncertain. Recover the original selectors and actual current claim,
read retained manifests, remeasure all results and return the same committed
receipt on an exact retry. Changed retry bytes conflict. A lost reply after
commit reads the durable original result without a second lane event or
deletion. A reclaimed claim requires fresh verification against that claim;
do not silently reuse a capability sealed for the previous claim.

The writer retains the removing claim before returning object journals to the
native remover. Reclaim preserves the original workspace journal and claim ID,
validates historical authority at the measured removal time and repeats fresh
reads under the current claim. The optional installed CleanupRemovalReadbacks
port authenticates that retained claim for VerifyCleanup. Missing historical
provenance or an unretained removing claim refuses.

| Implementing owner | Required implementation and refusal boundary |
| --- | --- |
| lb-v2-lifecycle | Select archived merged/abandoned lane, retain original clean cause and exact generation/epoch, resolve original cleanup intent on retry, and leave pending/refused until measured completion. Never substitute process collection for lane collection. |
| lb-v2-service/store | Implement CleanupObjectStore on the single writer, authenticated scope/claim, complete ownership and reference fences, real object operations/reads, retained manifests/journals and atomic CompleteCleanup/replay. Reject stale/revoked authority, partial inventories, changed bytes and missing native evidence. |
| lb-v2-admin | Implement WorkspaceCollector and protected journal/current workspace reads using enrolled root/repository handles, actual Git dirty/head decisions and unforced removal. Refuse foreign/replaced identities, dirty/unknown deletion, forced removal and unmeasured absence. |
| lb-v2-grants | Implement CleanupDataWorker orchestration using authenticated jobs, consume genuine release evidence, call the installed service/admin ports and VerifyCleanup, propagate every refusal/unavailability, and return the retained receipt without claiming completion itself. |
| lb-v2-serve2 | Measure installed authorized deletion, dirty/foreign retention, cancellation/reclaim/crash and lost-reply recovery, full audit preservation and real branch/worktree absence before closing G11. |

The cleanup-controls.json manifest wires the new deciding mutations into the
real red-controls.py loader and its loader regression. Its TestCollect paths
pair valid component records with authority, inventory, receipt, workspace,
independent read-back and completion refusals. Runtime controls must reach the
nominated assertion/diagnostic and then pass on the candidate in the authorized
Linux environment. Static vet on this Mac establishes compilation only;
native service/admin deletion and authenticated AI-service tests remain outside
this contract change.

Fix 14b retains both withdrawal controls and retargets their unique anchors to
the split helper validator. The Go-control runner preflights every edit, prints
and retains all missing/ambiguous anchors, and runs every constructible control.
Broken rows have status broken_anchor and null runtime exits; they never count
as reached failures or passes. Any broken row makes the final result nonzero,
with an explicit failure summary. The runner retains anchor-results.json and
per-row mutation/input evidence before execution. Runtime verdict errors still
stop their step. The three anchor-reporting/continuation/verdict self-controls
must fail at their nominated Python assertions before candidate acceptance.
