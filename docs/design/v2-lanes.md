# Laneboss v2 implementation lanes

This is the dispatch plan for the frozen [v2 contracts](v2-contracts.md).
It contains **24 lanes**, with **22 able to start immediately** against the
compiling stubs. It is a work plan, not evidence that any implementation or
acceptance has passed. The executor writing this plan starts no other sessions,
machines, live model calls or owner messages.

**R108 amendment:** self-hosted Clef-flash is the default judge, decided by the
owner. TypeSafe Jev stays pluggable. The Clef corpus calibrates thresholds;
there is no Jev comparison or two-week shadow requirement before using the
default or closing the Linux gate. Fit, complete answers, accounting, outages
and calibration remain required acceptance work.

The owner deadline is **2026-10-17 10:53 CST (UTC+08:00)**. The 36-hour clock
started with R102, not with each lane's dispatch. H0 below is the supervisor's
integration of this contract scaffold; compress milestones to the time actually
remaining without weakening acceptance. The table budgets about **216 engineer
hours** distributed across parallel lanes, including their focused tests. These
are estimates, not measured throughput; native macOS, vendor auth and human
verification are high-risk feasibility gates. Linux is the complete first
target; macOS develops in parallel and stays unavailable without native proof.
WSL2/Windows follow later.

## File ownership and merge rules

`cli/` in the ownership lists abbreviates **internal/v2/cli/**. All other paths
are repository-relative. `/**` grants a subtree including new files; braces
enumerate the named paths only. Every lane additionally owns
`e2e/v2/cases/<its suffix>/**` for its acceptance scenario, fixtures and
retained red-control specification. The harness owner owns e2e/v2's shared
runner and discovery, **excluding** every other lane's case subtree. No lane
edits a neighbor's case. The integration lane owns unlisted new shared files
only after recording their ownership here.

The root executable, Go dependency files, frozen API, composition root, common
CLI/parser and dispatch table belong exclusively to **lb-v2-integrate**.
Feature lanes implement their already-wired command file and module Register
method. They never edit a central switch/map or add a competing shared type.
The APIs have typed request/result objects, compiled interface assertions and
typed failing stubs; a missing dependency is not a reason to return success.
Report a needed contract amendment with consumers and evidence; only integration
changes the shared contract and updates all consumers together.

Integration additionally owns `internal/credentialtext/**`, a pure extraction of
the legacy judge's credential-shape detector. New service ports use it without
linking legacy local writers or provider subprocess code. Retire the old copy
only after its remaining callers have ported.
Integration also owns `cli/integrate_test.go` for common-parser and catalog
regressions. Feature command tests continue to belong to their feature owners.

Run-2 ownership clarification: integration owns **integrations/**, including
owner-sheet, Discord gateway, Claudock helpers and the remaining legacy cloud
integration sources, plus the confined RecordWorker/ResourceWorker and
authenticated OwnerIntake ports. This preserves the useful legacy contracts;
it authorizes no credential discovery, authentication, paid call or publication.
Integration owns scripts/scan.sh and scripts/scan_self_test.py. Other explicitly
assigned packaging/docs/platform scripts remain with their listed owners.

The supervisor additionally authorized integration to update the **current
consumer stubs together** for contract drafts .3 and .4. These coordinated signature,
dependency and typed failing-port edits do not transfer ongoing ownership of
feature implementations. After rebase, each feature owner replaces its own
contract_stubs with real behavior and evidence. No other worktree/branch is
edited and no neighboring implementation is silently copied over the stubs.

Existing legacy packages are read-only source/reference material for feature
lanes. Integration exclusively ports/edits remaining legacy `internal/**`,
excluding **all `internal/v2/**` feature ownership**, retirement's
`internal/orghook/**,internal/lanesandbox/**`, and packaging's
`internal/installation/**,internal/claudockcli/**,internal/identity/identity.go`.
Integration also owns remaining existing root scripts except the exact scripts
assigned to packaging/docs, and the new admin/Darwin/E2E script subtrees.
The docs lane owns only its listed guides/new docs/v2 subtree; it does not edit
docs/design or README/CHANGELOG. New role sources/examples belong to templates,
not docs. Platform unit/profile definitions are split into linux, darwin and
release subtrees. There are no simultaneous writers to these files.

Each lane submits its own complete file set and evidence. The supervisor
commits/lands; lanes do not add/commit/push real work merely because this plan
exists. Independent reviewers inspect read-only snapshots and send findings;
the owning lane makes fixes. Keep one active configuration binding per session.
A neighboring lane's code is reviewed as data; executing it requires the
child-bounded worker, never the parent's wider workspace.

## Waves and integration checkpoints

Development dependencies differ from runtime acceptance dependencies. Wave 1
has **no implementation lane that must land first**: all exported types,
interfaces and command slots already exist. Build a component against the
failing stubs, and use clearly identified fixtures only for focused wiring.
The per-lane dependency lists below name implementations needed for its full
black-box test; they do not require another lane's final sign-off first.
Integration assembles available implementations continuously, avoiding a cycle
where every author waits for another lane to be “accepted”.

| Wave / target after H0 | Dispatch and required checkpoint |
| --- | --- |
| 1, immediately; first slices by H6–12 | Start all 22 wave-1 lanes. Integrate and e2e start immediately as integration lanes, wiring/testing every landed slice. Foundation priority: service/store + identity + admin + Linux + grants + one runner. Prove service-owned state, actual confined start/report/stop and a real canary before feature claims. |
| 2, after the first installed vertical slice; H10–20 | Start docs against actual CLI/help/outputs; expand human proof, two drivers, lifecycle/tree, secrets/watchdog, policy/judges/guidance, D6 and dashboard. Migration/packaging keep the same artifact path. Run each feature case with independent negative/positive controls. |
| 3, only after the OS/service boundary gate; roughly H18–24 | Start retire-hooks after supervisor sign-off on exact pre-deletion OS/ordinary-work evidence. Remove the obsolete engine, then rerun the same controls on the changed artifact. No deletion on an executor's exit alone. |
| Final integration, reserve the last ≥10 hours; roughly H24–34 | Close every Linux parity/acceptance row, execute guides/install/upgrade/migration, run red ladder controls, then two simultaneous real mixed ladders on the identical final artifact. Complete independent Claude + Gemini cross-reviews and fixes, repeat affected cells, archive/read back and collect. Deadline pressure cannot turn incomplete rows into passes. |

If a foundation lane cannot provide its first runnable slice by H8, integration
records the exact blocking interface/capability and reorders independent work.
It does not bypass authentication or isolation. The schedule reserves repair
time; it does not promise that kernel/API/vendor feasibility will fit an estimate.

## Lane table

| Lane | Wave | Difficulty | Estimated hours | Purpose |
| --- | --- | --- | --- | --- |
| lb-v2-service | 1 | hard | 10 | Service socket, sole state writer, transaction/idempotency/outbox and client transport. |
| lb-v2-identity | 1 | hard | 12 | Kernel peer/lifetime identity, human confirmation, single-use tickets and strict identity derivation. |
| lb-v2-linux | 1 | hard | 10 | Production Linux bwrap/Landlock launcher, containment, syscall/network boundaries. |
| lb-v2-admin | 1 | hard | 8 | Administrator setup, bwrap-only AppArmor, root helper, UID/cgroup/network leases and doctor. |
| lb-v2-darwin | 1 | hard | 14 | Parallel native macOS peer identity and per-lane Seatbelt/account/network backend. |
| lb-v2-grants | 1 | hard | 10 | Parent-bounded data/resource grants and confined copy/Git/test/render/archive workers. |
| lb-v2-secrets | 1 | hard | 10 | Native encrypted secret storage, human import/rotation, task injection, private credential slots and refresh leases. |
| lb-v2-claudock | 1 | hard | 10 | Pinned claudock-cli adapter, private vendor home, explicit session continuation and authentic limit classification. |
| lb-v2-codex | 1 | hard | 10 | Pinned Codex adapter with private CODEX_HOME, actual conversation mapping, explicit resume and turn coverage. |
| lb-v2-watchdog | 1 | hard | 6 | Service watchdog quota swap and cancellation without changing logical task/budget/mail. |
| lb-v2-lifecycle | 1 | hard | 12 | Lifecycle/scheduler, capture, visibility, reviews, archives/clean and internal continuation. |
| lb-v2-messaging | 1 | hard | 6 | D7 tree messaging, upward reports, human channels and delivery outbox. |
| lb-v2-policy | 1 | hard | 8 | Layered settings, judged blacklist, skip optimization, cache and critical-only outage semantics. |
| lb-v2-judge | 1 | hard | 8 | Default self-hosted Clef-flash and optional TypeSafe Jev adapters, fit/bounds, normalized results and calibration evidence. |
| lb-v2-guidance | 1 | standard | 5 | Per-turn decision retrieval, judged relevance, recency ranking and persistent binding context. |
| lb-v2-approval | 1 | hard | 8 | D6 source/derived staging, operation-bound human approval and atomic application. |
| lb-v2-dashboard | 1 | hard | 10 | Human browsing UI/data API and authenticated mail/stop/resume/mark actions. |
| lb-v2-templates | 1 | standard | 5 | Role/task/grant brief rendering, source hashes, source templates and rule-list discovery. |
| lb-v2-migration | 1 | hard | 8 | Frozen legacy importer and reversible state/session/queue migration. |
| lb-v2-packaging | 1 | standard | 6 | One immutable executable/companion, checksummed release/source install and coherent upgrade/rollback. |
| lb-v2-docs | 2 | standard | 6 | Executed getting-started walkthrough, complete Traditional Chinese Linux operations guide and bootstrap ladder tutorial. |
| lb-v2-e2e | 1 | hard | 14 | Spot-box harness, executed OS/ordinary controls, evidence collection and final mixed ladder (integration lane). |
| lb-v2-retire-hooks | 3 | mechanical | 4 | Delete the obsolete hook protection engine only after the OS replacement gate passes. |
| lb-v2-integrate | 1 | hard | 16 | Sole composition/contract/legacy port owner, continuous vertical slices and final release integration. |

## Per-lane ownership, contracts and acceptance

### lb-v2-service

**Exclusive files:** `internal/v2/{client,service,store}/**`; `cli/commands_service.go`; `e2e/v2/cases/service/**`.

**Implements:** ServiceAPI, Store, Registrar, framing/digests/error/stream protocol. **Consumes:** Authenticator; all closed API/event schemas.

**Dependencies for full E2E:** identity for authenticated mutation cells; integrate for composition. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** SERVE-STATE: through the installed CLI/socket, append and read an authorized record, retry an identical mutation after dropping its reply and restarting the service, and observe one receipt/event/effect. Changed bytes under the key refuse. A lane direct-open canary on DB/WAL/journal fails; scoped RPC succeeds. A leaked state descriptor, duplicate effect, unknown JSON field, wrong schema, slow watcher or direct-DB outage fallback must fail the row.

### lb-v2-identity

**Exclusive files:** `internal/v2/identity/**`; `internal/v2/peer/linux/**`; `cli/commands_identity.go`; `e2e/v2/cases/identity/**`.

**Implements:** Authenticator, HumanVerifier, PeerVerifier, IdentityAPI. **Consumes:** Store, LaunchRecord, LaunchPermit, human challenge/proof.

**Dependencies for full E2E:** service, admin, linux for process/peer cells; dashboard for real browser proof. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** HUMAN-IDENTITY / PEER: connect real inside-namespace clients through the installed socket; authentic descendant and human-proof controls work. Forged actor/level/env labels, PID reuse, UID drift, stale launch, passed connected descriptor, wrong origin and a human-UID process lacking confirmation cannot mutate. Redeem one ticket once at its fixed role/level. Red controls omit containment/generation/proof/nonce checks and must be caught; hardware-presence evidence is separate from a credential-free authenticator fixture.

### lb-v2-linux

**Exclusive files:** `internal/v2/isolation/linux/**`; `e2e/v2/cases/linux/**`.

**Implements:** Launcher; port measured spikes/linux-iso at b38c634 from lb-spike-linux-iso. **Consumes:** Helper, LaunchSpec/Permit, Materialization, RunnerPlan.

**Dependencies for full E2E:** admin, grants, lifecycle, service, integrate for full launch acceptance. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** OS-LINUX: launch via CLI on Ubuntu restriction-on and restriction-off cells, hook absent/allow and vendor inner sandbox off. Execute real read / write / mmap / link / FD / Git / IPv4 / IPv6 / IPC / signal / double-fork canaries; observer proves ungranted files exist and stay unchanged. Own work/build/Git/network/temp/loopback controls succeed; stop leaves zero survivors. Repeat the ABI 3 floor. Broad-root mount, writable nested target, inherited FD, missing Landlock/network/cgroup denial or false zero survivors must fail. Missing prerequisites execute no agent.

### lb-v2-admin

**Exclusive files:** `internal/v2/admin/**`; `cli/commands_admin.go`; `cli/internal_admin.go`; `scripts/v2-admin/**`; `packaging/v2/linux/**`; `e2e/v2/cases/admin/**`.

**Implements:** Helper, AdminAPI, fixed internal helper mode. **Consumes:** ReleaseManifest, trusted service binding and peer identity.

**Dependencies for full E2E:** service, identity, linux for production helper cells; packaging for final artifact install. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** UBUNTU-DEFAULT / HELPER: on a disposable Ubuntu 24.04 box record actual restriction=1 and the unprofiled refusal, install/read back/reload only the bwrap profile, then unprivileged bwrap succeeds with unchanged switches and an unprofiled control remains denied. Through CLI doctor and launch, verify distinct service/lane UIDs, fixed helper executable and leases. Nonservice peer, arbitrary root argv/path, setuid workaround and changed artifact refuse. Restriction=0 requires no unnecessary profile while account/cgroup setup still works.

### lb-v2-darwin

**Exclusive files:** `internal/v2/isolation/mac/**`; `internal/v2/peer/darwin/**`; `packaging/v2/darwin/**`; `scripts/v2-darwin/**`; `e2e/v2/cases/darwin/**`.

**Implements:** Launcher, PeerVerifier for Darwin; LaunchDaemon/native lease definitions. **Consumes:** Helper/LaunchSpec and common service contracts.

**Dependencies for full E2E:** service, identity, grants, both runners, packaging; designated native test Mac. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** DARWIN-CAPABILITY: Linux spot CLI must report native backend unsupported and execute no agent. Native-only acceptance runs on an explicitly designated Mac: real audit-token lifetime/PID-reuse, world-readable outside canary, private UID/history, Seatbelt read/write/link/case aliases, recipient port/IPC, orphan stop and revoked lease, with positive own-work controls. Removing a profile/read denial or peer-generation check must fail. Do not run the whole suite on a development Mac or label Linux/darwin vet as native proof.

### lb-v2-grants

**Exclusive files:** `internal/v2/grants/**`; `internal/v2/dataworker/**`; `cli/commands_grants.go`; `cli/internal_grants.go`; `e2e/v2/cases/grants/**`.

**Implements:** GrantResolver, DataWorker, GrantsAPI and Object/RootGrant manifests. **Consumes:** Store, Launcher, grant/source handles and D6 render manifest.

**Dependencies for full E2E:** service, identity, linux, admin, lifecycle for full canaries. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** GRANT-BOUND / CHILD-CODE: CLI L5→L3 narrow file/repo grants succeed and match actual inside view; wider path / access / delegation / expiry / resource / secret requests refuse before launch. Recheck on resume/revocation. Independent Git objects cannot expose extra refs or common .git. Symlink swap/hardlink/nested mount/traversal fail. Execute an actual child test/Git hook attempting a parent-only canary under the review worker: denied; ordinary child-scoped build succeeds. Bypassing subset/FD resolution or running child code in parent authority must fail.

### lb-v2-secrets

**Exclusive files:** `internal/v2/secrets/**`; `cli/commands_secrets.go`; `cli/internal_secrets.go`; `e2e/v2/cases/secrets/**`.

**Implements:** SecretBackend, CredentialBroker, SecretsAPI. **Consumes:** HumanVerifier, Store, SecretGrant/ProfileGrant, ProcessObservation.

**Dependencies for full E2E:** identity, service, grants, linux, both runners; authorized broker for live cells. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** SECRET-INJECT / CREDENTIAL-BOUND: enroll synthetic canaries through human secret staging/import, inject one env and one file grant via lane start, compare in memory and print names/verdicts only. Undelegated values and reserved-variable replacement are absent/refused; event/archives contain no values. Restart without key cannot decrypt; valid protected recovery works; tampered ciphertext/AAD refuses. Concurrent login leases have one refresh owner, slot cleanup waits for quiescence. Broad inheritance/registry mount, plaintext fallback or subset bypass must fail.

### lb-v2-claudock

**Exclusive files:** `internal/v2/runner/claudock/**`; `e2e/v2/cases/claudock/**`.

**Implements:** Runner for claudock-cli. **Consumes:** RunnerRequest/Plan, CredentialSlot, primary CaptureRecord.

**Dependencies for full E2E:** secrets, linux, lifecycle, service; delegated live profile for authenticated gate. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** CLAUDOCK-TWO-TURN: use actual pinned vendor help/records and CLI start→resume→turn inside production isolation. Same private history/session/cwd survives a profile-slot change; sibling history/token cannot be read. Capture a real structured quota/usage result and reject quoted limit text/auth refusals as triggers. Wrong binary digest, shared-home symlink or lost conversation must fail. Credential-free fixtures prove wiring only; headless/helper/API subscription modes each need their own authorized live evidence.

### lb-v2-codex

**Exclusive files:** `internal/v2/runner/codex/**`; `e2e/v2/cases/codex/**`.

**Implements:** Runner for codex. **Consumes:** RunnerRequest/Plan, CredentialSlot, primary CaptureRecord.

**Dependencies for full E2E:** secrets, linux, lifecycle, service; delegated live login/provider. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** CODEX-TWO-TURN: real CLI start captures the vendor conversation identifier, explicit resume/turn returns a second planted answer with the same private history. Test a second concurrent lane and refresh serialization; no --last/shared home/keyring fallback. Outer sandbox remains effective with vendor inner sandbox disabled. Forged session, absent self-helper binary, borrowed sibling auth or falsely complete raw coverage must fail. Focused real L4/L5/L6 spawn/turn/wait cells gate advertised Codex supervisors.

### lb-v2-watchdog

**Exclusive files:** `internal/v2/watchdog/**`; `e2e/v2/cases/watchdog/**`.

**Implements:** Watchdog. **Consumes:** CredentialBroker, Launcher, internal Continuation, limit/capture/room receipts.

**Dependencies for full E2E:** claudock, secrets, lifecycle, service. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** WATCHDOG-LIMIT/NO-ROOM/TAMPER: through CLI start and event/dashboard reads, actual validated limit→quiescence→eligible profile B→same logical turn/history with one new run. Failure/retry counters and budget do not reset. Exhausted room waits/backoffs; restored room resumes once. Race manual stop/resume against pending swap, forge/quote a limit or tamper/kill watchdog from lane; none causes stale/duplicate continuation. A real limit afterward works. Bypassing actor/capture/room validation or duplicating mail must fail.

### lb-v2-lifecycle

**Exclusive files:** `internal/v2/lifecycle/**`; `cli/commands_lifecycle.go`; `cli/internal_lifecycle.go`; `e2e/v2/cases/lifecycle/**`.

**Implements:** LifecycleAPI, Continuation, EventStream producers and capture. **Consumes:** Store, Authenticator, GrantResolver, Launcher, both Runner adapters, CredentialBroker, templates/guidance/DataWorker.

**Dependencies for full E2E:** service, identity, admin, linux, grants, secrets, both runners; integrate. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** LIFECYCLE-TREE: CLI start→end→resume(run 2)→turn→stop→independent review→accepted→merged→archive→clean. Parent follow with saved sequence returns within 2 s of selected committed end under 20-agent load; older/hidden/observed ends do not stop it. Manual requester differs from carried sender; detached children are contained. Failed archive read-back, dirty/unowned work, unknown survivors, self-acceptance and cleaned resume refuse. Mutating actor selection, visibility, launch gate or receipt-before-delete must fail.

### lb-v2-messaging

**Exclusive files:** `internal/v2/messaging/**`; `cli/commands_messaging.go`; `cli/internal_messaging.go`; `e2e/v2/cases/messaging/**`.

**Implements:** MessagingAPI and fixed channel worker. **Consumes:** Store, authentic lives, ChannelGrant, logical-turn receipt.

**Dependencies for full E2E:** identity, lifecycle, service, approval for channel sources. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** MSG-REL / HUMAN-SEND: via inside CLI and dashboard send file-backed mail across actual same-parent siblings, ancestor→lower descendant and direct report line. Different-parent peers, cross-tree/upward skip and L3/L4→human refuse; granted L5/L6 channel succeeds through a disposable delivery fixture. Verified human→L3 succeeds, unverified identical request fails. Retry a partial delivery without duplicating confirmed send; reuse a lane name and verify no old rights. Skipped relation/delivery recheck or first-sender actor substitution must fail.

### lb-v2-policy

**Exclusive files:** `internal/v2/policy/**`; `cli/commands_policy.go`; `e2e/v2/cases/policy/**`.

**Implements:** PolicyAPI, EffectivePolicy/PolicyDecision. **Consumes:** Store, Judge, sources and defining-scope thresholds.

**Dependencies for full E2E:** service, identity, judge, approval; templates for list/brief integration. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** BL-RESP / SKIP: using CLI org blacklist list and actual hook/socket path, install D6-approved role-scoped cloud/PR/plugin denies. Judge membership refuses the matching action with Instead while unfamiliar unrelated work succeeds. Verify org+own+higher-role union, no lower-level inheritance, org fallback and preserved threshold authority. Change rules/role/context and prove cache/skip invalidation. Inject timeout/partial/cost cap: only explicitly critical refuse entries close; warn/noncritical allow with audit. An allowlist miss refusal, old pattern gate, stale cache or unscored-as-zero must fail.

### lb-v2-judge

**Exclusive files:** `internal/v2/judge/**`; `cli/commands_judge.go`; `cli/internal_judge.go`; `e2e/v2/cases/judge/**`.

**Implements:** Judge, JudgeAPI and provider adapters. **Consumes:** JudgeRequest/Reply, protected model/endpoint/credential config.

**Dependencies for full E2E:** service, identity for CLI; existing authorized self-hosted inference for live corpus. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** JUDGE-WIRE/BOUNDS: CLI judge ask sends retained exact requests to independently instrumented provider fixtures and the approved pinned self-hosted Clef endpoint. Assert command text remains state data, full probability mapping/model/deployment/latency and failure accounting. Oversize UTF-8/token-fit uncertainty / partial / malformed / echoed-wrong-model / timeout is unscored, not zero. Run the fixed approximately 302-item Clef corpus for threshold calibration and 1/12-question latency; no hosted Cloudflare account/token. Truncation, missing answer acceptance or lost egress reservation must fail. R108 selects Clef by default without a Jev comparison or shadow-promotion gate; separately verify the explicitly selected TypeSafe adapter remains compatible.

### lb-v2-guidance

**Exclusive files:** `internal/v2/guidance/**`; `cli/commands_guidance.go`; `e2e/v2/cases/guidance/**`.

**Implements:** GuidanceAPI and Guidance receipts. **Consumes:** Store decisions, Judge, Clock, logical turn.

**Dependencies for full E2E:** service, judge, lifecycle, templates. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** GUIDE-TURN: seed real decision records through CLI, run initial/resume/mail/idle prompt deliveries and inspect retained prompt/guidance receipts. Vary task and controlled service clock: recent relevant choices rank differently from old/unrelated ones; each turn selects, current binding policy never ages out, and only five reminders plus binding context appear. Empty is distinct from unavailable; profile continuation does not duplicate the logical-turn selection. Missing turn hook, cooldown, fake zero, age-expired binding policy or ignored task must fail.

### lb-v2-approval

**Exclusive files:** `internal/v2/approval/**`; `cli/commands_approval.go`; `e2e/v2/cases/approval/**`.

**Implements:** ApprovalAPI, ChangeRequest/Approval/Receipt. **Consumes:** Store, HumanVerifier, DataWorker.Render.

**Dependencies for full E2E:** identity, service, grants, templates; dashboard review path. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** ORG-APPROVAL: actual L6 submits script/tool/config/template/note changes through CLI, human reviews exact source+derived diff, approves, and application yields exactly those bytes/generation/receipts. L5 proposal, direct lane filesystem edit, stale base, wrong diff, generated extra effect, expired/replayed nonce and approval-policy shortcut fail without changing resources. Same idempotent retry returns original receipt. Omit any level/hash/base/nonce/human verification check in a red control and the row must detect it.

### lb-v2-dashboard

**Exclusive files:** `internal/v2/dashboard/**`; `cli/commands_dashboard.go`; `web/v2/**`; `e2e/v2/cases/dashboard/**`.

**Implements:** DashboardAPI, fixed HTTP/SSE routes and controls. **Consumes:** Identity/human proof, LifecycleAPI, MessagingAPI, ApprovalAPI, Store projections.

**Dependencies for full E2E:** service, identity, lifecycle, messaging, approval, records integration. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** DASH-* separately: on Linux spot, browse actual seeded decision/provenance, both-driver L3–L6 raw bytes/gaps/mail, live/configured tree, refusal/unscored counts, plugin loading, scripts/tools and approval history. UI lifecycle matches committed events ≤2 s. Browser stop halts actual processes; resume creates actual next run; reviewed mark merged/abandoned records truthful state; human mail reaches L3. Same unauthenticated / wrong-Origin / stale-proof actions fail. Stored HTML is inert. Hiding a capture gap, inventing empty inventory, accepting a label or bypassing proof must fail each relevant row.

### lb-v2-templates

**Exclusive files:** `internal/v2/templates/**`; `cli/commands_templates.go`; `templates/v2/**`; `examples/v2/**`; `e2e/v2/cases/templates/**`.

**Implements:** TemplatesAPI, TemplateRef and Briefing. **Consumes:** EffectivePolicy, GrantSet, retained task BlobRef, D6 sources.

**Dependencies for full E2E:** policy, service, approval, lifecycle for launch render proof. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** TPL-SCOPE / LB-FIRST: CLI brief/start prints the selected level/role, exact task, template generation/hash, grants, authentic report line and org blacklist list route. Keep source/rendered bytes and compare actual lane prompt. Missing local layer inherits org; malformed/wrong-role templates cannot widen rights. Exactly twelve seeded workflow entries retain Instead routes; unknown ordinary tools work. Wrong hash/generation, dropped task bytes, missing rule-list reference or bare-Claude driver catalog must fail. Briefing alone starts no agent.

### lb-v2-migration

**Exclusive files:** `internal/v2/migration/**`; `cli/commands_migration.go`; `migration/v2/**`; `e2e/v2/cases/migration/**`.

**Implements:** MigrationAPI, MigrationPlan/Manifest. **Consumes:** Store, HumanVerifier, DataWorker, old read-only format readers.

**Dependencies for full E2E:** service, identity, grants, lifecycle, integrate. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** MIGRATE-ROLLBACK: CLI plan/apply actual frozen 0.7.0 and candidate fixtures including 1.1/1.2 history, decisions / embeddings / mail / refusals / archives / owner queue and unfinished sessions. Compare every source hash/ID/sequence, verify new service read-back, no duplicate delivered mail and no imported active authority. Corrupt/missing evidence or active writers stop without changing originals. Relaunch selected history in new confinement; rollback restores matched old data+binary after retaining new work. Rehashed bad history, in-place ownership changes or label-derived parents must fail.

### lb-v2-packaging

**Exclusive files:** `internal/v2/distribution/**`; `cli/commands_packaging.go`; `internal/installation/**`; `internal/claudockcli/**`; `internal/identity/identity.go`; `install.sh`; `scripts/install.sh`; `scripts/release.sh`; `scripts/install/**`; `scripts/release/**`; `packaging/v2/release/**`; `e2e/v2/cases/packaging/**`.

**Implements:** PackagingAPI, ReleaseManifest, UpgradePlan. **Consumes:** Admin install artifacts, service version negotiation, human proof, migration.

**Dependencies for full E2E:** admin, service, migration, integrate; Darwin artifact metadata from darwin lane. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** INSTALL-UPGRADE: fresh Linux spot source installer and supplied-artifact path verify exact binary/helper/client/vendor hashes and version negotiation; no runtime Go/Python/Node needed for release binary. Install service/helper with actual unit/profile assets, then CLI start/status. Tampered download, mismatched client/helper/schema, interrupted migration, incomplete backup or live old writer refuse. Upgrade quiesces/drains and rollback restores matched frozen state without losing new history. Removing checksum/read-back or silently relinking old code onto new data must fail.

### lb-v2-docs

**Exclusive files:** `docs/getting-started.md`; `docs/check-bootstrap.sh`; `docs/configuration.md`; `docs/service.md`; `docs/install.md`; `docs/claudock.md`; `docs/org.md`; `docs/org-hooks.md`; `docs/judges.md`; `docs/decisions.md`; `docs/v2/**`; `scripts/demo-screenshots.sh`; `scripts/demo_shots.py`; `e2e/v2/cases/docs/**`.

**Implements:** User-facing instructions derived from frozen CLI/RPC and accepted product behavior. **Consumes:** Packaging/admin, every public feature, retained real examples/evidence.

**Dependencies for full E2E:** packaging, service, lifecycle, identity, templates, grants; e2e/integrate for final guide runs. Start after the first installed vertical slice.

**Black-box acceptance:** DOCS-EXEC: checker executes every actual guide block in order on disposable Linux with source and supplied-binary modes, retains input/binary/transcript/state and requires exit 0 plus PASS: getting-started walkthrough. Exercise administrator setup, human verification, both supported drivers, D6/D7/D9, task secrets, dashboard and day-2/archive flow; stand-ins are clearly separate from live auth. Guide wrong flag/hash, missing pass line, stale no-dashboard text or omitted step must fail. Use synthetic privacy-checked screenshots; do not turn unavailable Mac/live cells into passes.

### lb-v2-e2e

**Exclusive files:** `e2e/v2/** except other lanes' case subtrees`; `scripts/v2-e2e/**`; `e2e-rows/v2/**`; `e2e/v2/cases/e2e/**`.

**Implements:** Black-box acceptance runner, independent observers/red controls, final ladder. **Consumes:** All public CLI/socket/dashboard contracts and all case manifests.

**Dependencies for full E2E:** all Linux feature lanes, packaging, docs, retire-hooks and integrate for final gate. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** E2E-LADDER: source/release install on one authorized spot box; run two concurrent separately bound ten-instance ladders, actual service/OS backends and pinned real drivers. Harness starts only L6. Recorded seed chooses mixed L3s; independent unpredictable tokens/path and causal ping/pong flow up authentic parents, which review/archive/clean children. Red controls reject wrong token/path, missing ancestor, upward skip, early PONG, hidden end, mail-sender actor, missing transcript and surviving process before paid runs. Verify both simultaneous runs, capture/state/artifact hashes and actual machine termination. Neither sequential passes nor a fixture/all-Claude run can pass the real mixed gate.

### lb-v2-retire-hooks

**Exclusive files:** `internal/orghook/**`; `internal/lanesandbox/**`; `retirement/v2/**`; `e2e/v2/cases/retire-hooks/**`.

**Implements:** Isolation design §7 exact deletion map and historical fixture preservation. **Consumes:** Accepted OS/service boundary and ordinary-work evidence; policy RPC.

**Dependencies for full E2E:** linux, admin, identity, grants, lifecycle, policy, e2e first OS acceptance; integrate for outside callers. Do not start deletion before the named OS gate.

**Black-box acceptance:** HOOK-REMOVAL: require signed-off exact pre-deletion OS evidence, then remove prediction/write/boundary/obscured-call code and broad bypasses. Re-run the same CLI/OS canaries with hooks absent/allowing and inner vendor sandbox off, plus explicit blacklist and ordinary-work controls. Preserve original private/public row inventories with each mapped to an executed boundary or policy row. Any lost syscall denial, residual command-text protection dependency, ordinary-work regression or unmapped row fails; compilation/search alone is not acceptance.

### lb-v2-integrate

**Exclusive files:** `internal/v2/api/**`; `internal/v2/assembly/**`; `internal/v2/records/**`; `cli/{cli.go,dispatch.go,serve.go,commands_integrate.go}`; `cmd/laneboss/**`; `go.mod`; `go.sum`; `docs/design/v2-contracts.md`; `docs/design/v2-lanes.md`; `all remaining legacy internal/** except explicit retirement/packaging ownership`; `README.md`; `CHANGELOG.md`; `e2e/v2/cases/integrate/**`.

**Implements:** Composition root, contract amendments, records/decision/search/cloud-worker ports, parity inventory and gate closure. **Consumes:** All component interfaces, every lane's evidence and independent reviews.

**Dependencies for full E2E:** starts at freeze; final acceptance depends on all Linux lanes, docs, e2e and retire-hooks. No implementation prerequisite for starting development beyond the contract freeze.

**Black-box acceptance:** INTEGRATED-RELEASE: actual installed binary owns all 24 legacy command groups through typed socket routes with no old local writer. Validate every isolation.md §8 port row and command alias, records / vector / archive / cloud / report / owner-sheet / gateway behavior in confined workers, and CLI/socket/dashboard parity. Lost-reply/restart, denied direct state, cross-config overlap, D6 change, profile continuation and two concurrent ladder cells pass on identical artifacts after hook deletion. Missing RPC/handler, surviving stub, constant response, third driver or legacy fallback fails. Gate on independent Claude review plus opencode google-vertex/gemini-4-argon cross-review; reconcile findings before acceptance.

## Harness and evidence interface

Each case is discovered from its own subtree; feature lanes never modify a
central test dispatch table. The e2e owner implements a small versioned
`case.json` reader with this frozen shape:

```json
{
  "schema": "laneboss.e2e-case.v2",
  "id": "service",
  "owner": "lb-v2-service",
  "platforms": ["linux"],
  "requires": ["service", "identity"],
  "entry": "run.sh",
  "timeout_seconds": 1800,
  "live_auth": false,
  "assertion_ids": ["SERVE-STATE"]
}
```

The runner invokes each entry with exactly
`--context CONTEXT_FILE --result RESULT_FILE`; no positional arguments or
implicit shell-variable contract. Both are absolute paths inside the case's
disposable test scope. CONTEXT_FILE is read-only JSON:

```json
{
  "schema": "laneboss.e2e-context.v2",
  "case_id": "service",
  "phase": "candidate",
  "mutation_id": "",
  "binary": "/test/artifacts/laneboss",
  "binary_sha256": "<64 lowercase hex digits>",
  "source_sha256": "<64 lowercase hex digits>",
  "config": "case-service",
  "binding_file": "/test/bindings/case-service.json",
  "test_root": "/test/cases/service",
  "evidence_root": "/test/evidence/service",
  "profile_grant_ids": []
}
```

Paths are harness-created, not arbitrary authority to read another case.
Phase is `red|candidate`; red names the deliberate mutation and its distinct
artifact digest. Profile grant IDs contain names/handles only. No secret value,
vendor home, environment dump or human confirmation token enters this file.
The entry writes RESULT_FILE atomically with this exact shape:

```json
{
  "schema": "laneboss.e2e-result.v2",
  "case_id": "service",
  "phase": "candidate",
  "mutation_id": "",
  "binary_sha256": "<64 lowercase hex digits>",
  "source_sha256": "<64 lowercase hex digits>",
  "assertions": [{
    "id": "SERVE-STATE",
    "reached": true,
    "verdict": "pass",
    "observed_exit": 0,
    "evidence": [{
      "path": "socket/transcript.jsonl",
      "sha256": "<64 lowercase hex digits>",
      "bytes": 123
    }]
  }],
  "collection": {
    "processes_quiescent": true,
    "temporary_resources_collected": true,
    "evidence": []
  }
}
```

Verdict is `pass|fail`; there is no skip/unknown-as-pass. Evidence paths are
relative to evidence_root and must resolve beneath it without escaping links.
The runner verifies actual file sizes/hashes, observed process exit, all
declared assertion IDs exactly once, artifact identity and independent
canary/state observations. The illustrative byte count above is not an expected
constant. Candidate entry exit must be 0 and every reached verdict pass.
A red entry intentionally returns nonzero with the targeted **reached failing**
assertion; the shared runner records a killed mutation only when the independent
operation evidence proves the intended failure, never for a setup crash.
Unexpected failure stops the phase. Missing result, mismatched hashes or an
uncollected owned process/resource prevents acceptance even with exit 0.

The entry is relative to the case directory, run only in the authorized test
environment and with a harness-supplied installed artifact/binding. It must
exercise public CLI, socket or dashboard behavior and emit a structured result
file with assertion ID, observed verdict, command exit, input/output object
hashes and evidence references. Exit 0 alone is insufficient. The shared runner
verifies all declared assertions were reached; missing result/evidence, skipped
cells, unexpected process survivors or a nonzero exit fail. Fixture/hardware/live
modes are separate named evidence cells, never a substituted result for one
another. No production API chooses a fixture/third driver or a fake auth pass.

Every new assertion is first demonstrated failing for its intended reason
against a deliberate red control, then passing against the candidate. Use one
minimal assertion/control and a guarding mutation per distinct boundary;
variations in spelling are table data. A red run that failed setup before
reaching the operation does not count. Never use a constant pass, expected
answer embedded in a runner, swallowed error, test skip or fabricated errno.

All builds, unit tests, interpreters and Linux E2E run on an authorized
disposable Linux spot machine, at most one machine per lane at a time, following
the configuration's launch/cleanup files. The local authoring Mac permits only
the requested static checks; native tests are Darwin-only on an expressly
designated test Mac. This plan itself authorizes no machine, secret transfer,
authentication, model request or paid service. Use names-only credential grants
and an approved broker for live cells, never credentials in checkout/fixture HOME.

Required Linux coverage includes amd64 and arm64 artifacts, Ubuntu 24.04
restriction **1** with the bwrap-only profile and unchanged host switches,
a measured restriction **0** control, Linux 6.6/ABI 3 floor, missing-prerequisite
refusal and below-floor unsupported results. The earlier spike's 185/185 and
195/195 results are credited as feasibility, not reused as product acceptance.
Measure 100 warm and separate cold launches with p50/p95/RSS/materialized bytes;
the old 20 warm true launches cannot establish startup performance.

Retain source/input archives, exact tested binary/helper/vendor bytes and hashes,
source revision, OS / kernel / LSM / bwrap / architecture / capability facts, installed
profile/unit/binding/grant bytes, commands, exits, stdout/stderr, primary capture,
state/events, request/result receipts, per-assertion evidence and collection
status. Source manifests exclude credentials and private denylist bytes.
Place protected evidence outside the checkout under each lane's evidence root;
copy/read back/hash at every phase before collecting a machine. Keep failures.
Report the actual measured path and scope. If a guard refuses, stop and report
its exact text and command prefix; use only its allowed recovery route.

## Final ladder and release gate

The primary ladder is **ten instances: 1 L6 + 2 L5 + 3 L4 + 4 L3**.
L6/L5/L4 are Claude Code through **claudock-cli**. A recorded random seed
assigns the L3 mix, guaranteeing both Claudock/Claude and Codex (shuffle two of
each). The harness starts only L6. Authentic parents spawn their lower-level
children through the inside CLI, wait on their correct run end, review, mark,
archive, clean and report upward.

Each instance must find its own independently unpredictable planted token/path;
the random structure seed never determines the answer. Parent reports include
all descendant answers through the direct report line. Ping/pong proves send
event → delivered turn → matching child response; early PONG is rejected.
Require simultaneous sibling starts and a second credentialed turn, correct
manual actors distinct from carried senders, parent-visible ends ≤2 seconds
after durable commit, sibling privacy, unchanged source trees, real budgets/
exits/zero survivors, complete primary/raw evidence, no unexplained refusal or
suspicion and verified archive/cleanup by parents.

Before paid/live runs the exact same acceptance code must reject wrong
token/path, another lane's path, missing ancestor answer, upward skip, early
PONG, a hidden/historical/fake child end, first-mail-sender actor, missing
transcript, absent immutable executable and surviving child. Fixture wiring
and all-Claude diagnostic ladders do not pass this gate.

Run **two complete primary ladders concurrently on the same authorized spot
machine**, with separate configuration / store / socket / UID / workspace bindings,
the same seeded runner structure and independent planted tokens. Sessions never
switch bindings. Capacity/quota loss that prevents concurrency leaves this
gate incomplete; two sequential successes are insufficient. A validated
watchdog profile swap is continuation, not a failed/retried task, and cannot
duplicate prompts/mail or reset spend/time.

Focused pure-Claudock/Codex adapter cells, real Codex-supervisor L4/L5/L6
delegation/turn/wait, selected authentication modes, all DASH view/action cells,
migration/rollback, executed tutorial and post-deletion OS canaries are separate
requirements. No single page load or one real API-key request proves them all.
Native macOS retains its own support matrix; unproved native cells are unavailable,
not passed by Linux evidence.

`lb-v2-integrate` owns the final feature/command parity ledger against
isolation.md §8, with each row mapped to an implementation and actual evidence.
`lb-v2-e2e` independently runs the final artifacts. Gating reviews additionally
require an independent Claude read and **opencode using
google-vertex/gemini-4-argon** under R103; compare findings, fix through the file
owner and retain both review records. No author accepts its own production lane
solely because the executor exited successfully.

Release acceptance requires all required Linux rows green on the exact final
source/binary, review findings resolved, complete retained evidence and verified
collection. Publishing, merging and owner messaging remain the supervisor's
separately authorized operations. A schedule or a compile does not authorize them.

## Open points with assigned owners

These are evidence/operational gates, not requests to reopen the brief's chosen
defaults. Record changes through the contract owner if a proof falsifies a
proposed capability.

| Open point | Owner and disposition |
| --- | --- |
| Actual pinned Claudock/Codex auth, refresh, raw format and explicit session support inside the outer boundary | claudock/codex/secrets; fixture success is insufficient. Unsupported modes stay unavailable; no paid fallback. |
| Linux floor, helper/egress/SCM_RIGHTS/race coverage beyond the spike | linux/admin/identity/e2e; run real canaries and controls. |
| Native Darwin identity/Seatbelt/network listener feasibility and designated Mac | darwin; parallel work, Linux first, no unsupported native claim. |
| Human authenticator/origin enrollment and real presence proof | identity/dashboard/approval; no UID/token-only administrative substitute. |
| Clef tokenizer fit and approximately 302-item threshold calibration | judge/policy; self-hosted default under R108, self-hosted only under R101. Retain optional TypeSafe compatibility. The default is decided; no Jev comparison or shadow-promotion period is required. |
| Complete private write-shape inventory and preserved historical fixtures | e2e/retire-hooks/integrate; unmapped rows prevent an “all converted” claim. |
| Initial root resource/secret/profile/channel grants and archive/recovery enrollment | supervising human plus grants/secrets/approval; explicit names and actual authorization, no host environment discovery. |
| Independent reviews and exact final artifact acceptance | integrate/e2e plus supervising review sessions; this contract lane performs static checks only. |

## Integration checkpoint: wave 1

This checkpoint is source work, not INTEGRATED-RELEASE acceptance. The executable
uses v2 only; it cannot fall back to the legacy local writers. Common exact
`--request FILE` parsing and integration record flags use the socket client.
All feature-specific ergonomic flags still need their owners' implementation.
The composition root constructs every frozen module, registers owned routes,
and refuses absent runtime/watchdog wiring. Current dependency constructors
remain failing stubs. No installed service, confined model, kernel canary or
release run is claimed by this checkpoint.

Draft.2 contract amendments and the consumers that must rebase are recorded in
v2-contracts.md §13. Service/store must retain `RecordResult` and implement exact
record filtering; service must implement ServiceHost, lifecycle must bind the
watchdog, and judge/policy must adopt R108. These additions leave existing method
signatures compiling against the freeze, but fail explicitly until runtime
consumers implement the required behavior. Human decision authority is tightened
to match isolation.md §4/§8. No external review or artifact acceptance has run.

The integration case folder contains two source inventories:

- `ports.json` maps **all 76** rows of isolation.md §8 to target packages and
  required cases, preserving each original feature/disposition/destination.
  Every row remains `pending` with no evidence until executed acceptance and
  independent review populate it on the final artifacts. Drop rows require
  post-deletion behavioral evidence, not a grep result.
- `commands.json` records the **75** legacy leaf declarations in the frozen
  syntax source and the **147** reserved v2 CLI routes. All 75 declarations have
  a reserved typed route; this is a source inventory only. The dynamically
  dispatched operations below must additionally be exercised. Help/registration
  alone cannot close a command row or prove its legacy semantics.

The complete 24-group inventory from the old root dispatcher is:

| Legacy group | Typed destination / port owner | Acceptance still required |
| --- | --- | --- |
| init | org.bootstrap / templates, admin | Source/render transaction, no agent launch, root enrollment. |
| store | records and store.verify/rebuild / integrate, service | Screening, scope, keyword/vector/history, original replay receipts. |
| archive | lane.archive / lifecycle, grants | Daily inventory, manifest/hash/read-back before removal. |
| decisions | records, decisions.mutate, migration / integrate | Full import/export/embed/search/stats semantics and human/D6 provenance. |
| plugin | config.read plugins / policy, templates | Legacy arguments, exact manifests and actual loading. |
| org | typed templates/policy/approval/records / corresponding owners | Every roles/channel/render/history/blacklist action; D6 for edits. |
| config | config.read/validate / policy | List/show/path/validate and warnings/provenance. |
| event | event.tail, records.append / lifecycle, integrate | Observation cannot forge authoritative end; bounded streams. |
| state | lane.list, event.tail, store.verify/rebuild / lifecycle, service | Projection and rebuild authority, no direct DB. |
| settings | config.read settings / policy | Dynamic get/list/explain, exact layered values and sources. |
| brief | brief.render/start / templates | Exact sources/tasks/budgets; Markdown and JSON parity. |
| lane | lifecycle/mail/records / lifecycle, messaging, integrate | Full lifecycle, turns, loop, attach, coverage, review, archive and clean outcomes. |
| judge | judge.ask/list, records.query / judge, integrate | Clef default, explicit TypeSafe alternative, bounds and egress accounting. |
| disk | doctor plus lifecycle filesystem latch / admin, lifecycle | Actual filesystem thresholds/latch, honest failed measurement. |
| doctor | doctor / admin | Installed prerequisites and unsupported diagnostics. |
| start | brief.start / templates | Briefing only; no host-session open registration. |
| ticket | ticket.issue / identity | Exact level/role/grant, verified human, one-use/replay/expiry. |
| service | health and serve / service, integrate | Dedicated installed hosting/recovery; old identity-only run is replaced. |
| report | report.submit/mail.list / messaging | Direct upward relation, per-channel outcomes, retained exact artifact. |
| dashboard | dashboard.* and existing typed mutations / dashboard | Every view/action, actual human/Origin/proof, same committed data. |
| ledger | records.query ledger / integrate | Only verified outside workers create fresh resource/cost facts. |
| refusal | records.query refusals / integrate, lifecycle | Raw coverage/refusal/suspicion drill-down, no empty-unavailable success. |
| tool | records.query tools / integrate, lifecycle | Verified primary capture versus untrusted observation. |
| box | box.* / integrate, grants | Confined AWS/GCP grants, fences, budget, run, harvest/read-back, end/orphans. |

The freeze has semantic gaps that are not closed by its aliases. `decisions stats`
still has no aggregate RPC and therefore returns not_implemented. The current
WorkerPlan/DataWorker surface does not yet implement confined record
import/export/vector/embed or cloud provisioning/collection; draft.2 names the
required optional RecordWorker/ResourceWorker seams and keeps those calls
failing. Dynamic `settings get/list`, decision history ingestion/resident search,
org history workers and migration need explicit behavior/alias tests rather
than forwarding their old argv. Owner-sheet round trips and receive-only gateway
restart/sender/channel semantics need integration tests plus the authenticated
human/channel intake seam; a lane cannot submit a human label through mail.send.
The supervisor assigned those existing integration sources and intake ports to
integration in run 2. Existing restart/history gaps remain documented. None of
these rows is waived or passed.

Final gate closure additionally requires lost-reply/restart, denied direct
state/FDs, cross-config writable overlap, exact D6, profile continuation,
CLI/socket/dashboard equivalence, hook deletion and the two concurrent mixed
ladders. Run those on the identical source/binary/helper/vendor set. Retain an
independent Claude review and opencode google-vertex/gemini-4-argon cross-review,
resolve findings through file owners, then rerun affected cells. This lane does
not start review sessions or accept its own work.

### Wave-0 package retirement sequence

| Package | Port/consumers | Removal gate |
| --- | --- | --- |
| internal/isolation | Linux/Darwin/admin/grants/lifecycle use the v2 Launcher/Helper contracts. The wave-0 directory is absent from this baseline and exists only in other lanes' incoming work. | Supervisor first lands the consumers and exact OS/ordinary-work evidence, compares the incoming sources, then removes the old package through its owner. No active hook deletion ahead of retire-hooks. |
| internal/runnerhome | Claudock/Codex/secrets/lifecycle use private Home/Session/Slot and credential broker contracts. The wave-0 directory is absent from this baseline. | Two-turn/session/refresh-isolation evidence and profile continuation on both drivers, with no remaining incoming imports, precede removal. |
| internal/judge | Legacy adapters, ledger, dashboard, decisionsrv, CLI, orghook and the legacy helper command still import it. The wave-0 package overlaps an existing package name and must not be blindly deleted. `internal/credentialtext` preserves its pure screening logic without linking its local writers/subprocesses into v2. | Port wire validators/fixtures and all active consumers to v2 judge/policy/guidance/records; preserve historical readers/evidence. Packaging stops shipping legacy helper binaries; retire-hooks owns its callers. Verify no remaining incoming imports and rerun affected judge/guide/record cells before a separate removal. |

No wave-0 package is removed in this checkpoint. Search/compilation alone is
insufficient to authorize removal, and integration never edits another lane's
worktree to make that search look clean.

## Run-2 contract consolidation and handoff

The next shared revision is **v2.0-draft.3**, including draft.2, all ten supplied
amendment notes and R108. The exact decisions, API types, signature changes and
per-request consumer matrix are in v2-contracts.md §14. Rebase on the complete
supervisor-landed integration change set after review; its commit does not exist
until laneboss stages/reviews/commits this work. Do not rebase on an api-only
partial copy or treat the unchanged base d6f2a96 as the new revision.

Every Linux lane consuming api must rebase: service, identity, linux, admin,
grants, secrets, claudock, codex, watchdog, lifecycle, messaging, policy, judge2,
guidance, approval, dashboard, templates, migration and packaging. Darwin must
also rebase its helper/peer/runtime wiring. E2E/docs consume the new bindings,
wire maps, controls and behavior; retire-hooks still waits for the real OS gate.
Feature owners resolve their implementation/fixture conflicts against their own
slice, using the updated baseline stubs as the signature reference. Integration
did not check out or write any of the source branches used to read the notes.

The consolidated store contract now includes exact typed result/error receipts,
reservation/replay before module preflight, atomic proof/ticket/counter/approval
guards, typed state writes and effect claims/completion, pinned read snapshots,
approved source/turn/decision projections and deployment plan lookup. It removes
the record-only reply special case. HelperControl adds committed gate control,
abort/reconciliation and protected runtime/containment resolution. Constructor
wiring supplies these ports and the scoped judge, publisher, delivery and
deployment dependencies. All newly missing implementations still fail explicitly.
This is a source-contract checkpoint, not a passing installed service or release.

R108 remains unchanged: Clef-flash is the default, TypeSafe is explicitly
pluggable, and the corpus calibrates thresholds without a comparison/shadow gate.
The expected judge2 batch concern is already represented by Rules/Decisions
arrays; draft.3 additionally retains every request/batch audit reference. Any
later exact judge2 amendment must be reconciled before acceptance.

The supervisor approved one publication-scanner exception: only a long-token
match entirely inside the quoted path of a whole-line own-module Go import.
The lexer excludes string/comment lookalikes and nested expressions; optional
aliases and the single-line import form are supported. File-wide, package-wide,
substring, foreign-module, other-file and other-rule exemptions remain absent.
The existing go.sum exception is unchanged. The retained red/positive scanner
self-test is scripts/scan_self_test.py; run it on the disposable test box:

```sh
python3 scripts/scan_self_test.py --evidence /test/evidence/integrate/scan
```

It requires actual scanner exit 0 on own imports, and exit 1 with the expected
rule on long literals, import-looking strings/comments, foreign imports, trailing
comments, other files and other-rule input. Inputs and stdout/stderr/exits remain
under its temporary evidence subtree. A constant scanner success/failure cannot
pass both sides. On the authoring Mac only its static compilation/shell syntax
and the requested Go static checks run. Laneboss alone stages and performs the
post-staging scan; this executor never runs git add.

## Run-3 draft.4 review corrections

Draft.4 builds on the supervisor-landed `94b2cc9` draft.3. Keep the existing
implementation rebases; apply the exact delta/consumer table in
v2-contracts.md §15. There is no new public RPC or production driver. The
connection handoff now has a single transport → peer/containment → identity
order. Admin/lifecycle/store use helper_prepare/register/release and a measured
ReleaseReceipt. Store consumes the explicit method/write/event/effect matrix,
new Grants / JudgeAudits / Channels / WorkerLeases projections, retained decision
lookup, required replies and append-only supersession events. Watchdog submits
only Swap's continuation fence. Judge resolves approved policy before choosing
the lazily wired Clef/TypeSafe enrollment, with real deployment/tokenizer pins.

Service/client and all feature CLI owners retain mutation keys. Human-read
`--proof` establishes human.session on the command's shared live socket. Human
record/decision callers upload first, then confirm and submit the known
`--content-ref` with that exact operation proof. E2E's integration cell now
retries its append with the retained key and checks the actual judge.ask reply
and deployment against an independently instrumented credential-free fixture.
The real service/provider implementations remain prerequisites for that cell;
no live model call is authorized by these changes.

Scanner regression fixtures use real temporary Git indexes, testing 19 inputs
in both working and staged modes. The exemption requires this module's go.mod
and tracked regular Go package directory; an indexed package/module remains
authoritative for --staged even when working bytes differ. Existing patterns,
denylist handling and the exact go.sum exception remain unchanged. The controller
schema also applies the same relative evidence-path constraint in every result
and error branch. Only requested static checks run on the authoring Mac; the
supervisor supplies positive/red unit, scanner and hosted evidence on Linux.
