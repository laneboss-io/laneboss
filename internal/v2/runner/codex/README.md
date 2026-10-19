# Codex adapter

This package implements the frozen api.Runner plan/capture interface and the
Codex consumer through draft.4 fix 12. It starts no process, makes no provider request,
authenticates no account and reads no ambient credential or shell environment.
Its current parser/adapter receipt version is codex-exec-v4.

[Fix-12 adoption](FIX12-ADOPTION.md) describes descriptor-only refresh, the
final-exec task environment gate, logical turn identity, current approved
policy, usage claim timing and closed effect states. The current inventory is
190 Go forms in both builds (380 rows) and 23 protocol controls; older evidence
counts below describe their earlier revisions. Native transfer, canonical
write-back and actual final exec remain owning admin/secrets/helper gates.

Start, Resume and Turn borrow an authentic operation ReadScope and its live
ReadView. Planning.Lease and AllocationEffectID are service-owned selectors:
each call reloads the current effect claim, LaunchPlanRecord, original
launch_request bytes and original mutation receipt. It compares the reserved
life/run, requester/request/operation, policy, grants and cancellation epoch.
The reserved Level, Role and Driver are authoritative. The original start must
agree with them and its consumed ticket; retained runs must agree with the prior
reservation and current life, and human runs retain the original proof ID and
intent digest. Supervisor capability uses the reserved level.
A new start consumes a sourced reservation before a ready Lane exists. It
never fabricates a Lane to make that stage succeed.

Sources.ResolveLaunchSources revalidates the protected enrolled project and
runtime. The returned Codex Executable must equal both the retained selection
and installed Runtime. A sourced reservation additionally needs DataStageID, its original child stage,
validated completion/read-back and a succeeded child effect. AwaitMaterialization
is service-owned; the adapter never runs copy/Git or claims that effect. A complete
planned/spec_retained record can reuse its already validated data. Allocation comes from the original successful helper
effect, not a supplied path or lease label. Storage.ResolveLaunchStorage
returns the helper journal's life-owned workspace/home IDs and root-relative
.codex descriptor. Store.Turn must return the retained prompt selection;
ResolveSession must reload the protected prepared session. All pins are
compared before returning argv. There is no permissive fallback for an
unimplemented or missing dependency.

A retained run reads PreviousLaunchID's complete LaunchBinding recovery tuple
and original spec bytes. Its ended life, private session/home/history, runtime,
model, logical cwd, budget request and generations must agree. The new
allocation must preserve the prior PrivateHomeBinding, including RootID and
generation, and workspace ID. A sealed replay must produce the same RunnerPlan
and retained inputs. The adapter does not open or reconcile a process gate.

The composition must create an operation-scoped runner from trusted stage
selectors and keep the borrowed read view alive through the call. Do not mutate
one shared runner's dependencies for concurrent operations. The frozen
RunnerRequest contains no PlanID or Scope, so this constructor wiring remains a
lifecycle/service/assembly integration requirement. See
[LAUNCH-PLAN.md](LAUNCH-PLAN.md) for the consumer map, deciding controls and exact
Linux acceptance rows, and [CONTRACT-GAPS.md](CONTRACT-GAPS.md) for owner work.

Only the pinned Codex executable's fixed exec/resume argv is constructed.
The exact prompt is a committed BlobRef delivered on stdin, never argv or an
environment value. There is no --last, generic command forwarding, PATH-only
vendor selection, shared home or paid provider fallback. File-store,
approval_policy="never", sandbox_mode="danger-full-access" and reasoning effort
are explicit argv settings; sealed config repeats the file/approval/sandbox
settings. The outer OS boundary and committed launch gate remain mandatory.

**Resume argv against the pinned CLI remains unverified.** The earlier public
reference fetch failed DNS resolution, and no pinned help/version artifact was
supplied. **A real provider-limit sample also remains unverified.** Existing
mode keys and synthetic parser fixtures are construction evidence only.
Packaging must retain exec/resume help, effective mode and actual file-login,
continuation, workspace write/read and provider-limit observations before
installing an independently reviewed receipt. Older adapter receipts cannot
enable codex-exec-v4. API/local credential modes remain not_implemented.
L4/L5/L6 each require their own real spawn/turn/wait compatibility receipt.

SessionFromCapture and LimitFromCapture require an original primary record
with BindingID, capture class, honest partial/unsupported coverage and a
service-origin event/object. They read CaptureState, the bound/opened plan,
complete recovery tuple and original spec bytes. A registered binding, matching
original cause, unique committed capture.bound and actual identity.bound event
must precede the consumed ranges. Refused capture requires explicit allowed,
approval and policy-generation metadata, the retained plan's policy snapshot,
and a matching protected current D6 policy. The publisher/store must verify
actual consumed D6 authority and recheck revocation before release. Only then
does the consumer return the original owning refusal; it returns no session or
limit. Sealed replay of a refused plan also rechecks protected current policy.
A prior refused capture blocks Resume/Turn.

Opened capture reads preserve the sealed reservation/grant policy generation
across D6 advances, with exact snapshot, expiry and Revoked checks. Unknown/future
history still refuses. Scoped store reads must enforce current authentication,
control rights, visibility and revocation. Fresh launches still require current
policy; historical replay cannot authorize a new action under old policy.
Missing bindings, replacements, supplementary transcripts, changed storage,
unknown positions and gaps in the selected stream cannot establish a session
or limit.

Chunks are reconstructed contiguously and checked against retained object and
chunk hashes, source operation, life ACL and acknowledged offsets. A complete
thread.started prefix can be used while a later JSONL line is incomplete.
Final limit analysis also requires acknowledged EOF with matching binding,
stream, range, generation and committed sequence. Vendor lines use the 64 MiB
object bound; configuration/private records retain their smaller bounds.
Typed records use api.DecodeObject; variable vendor JSON enforces duplicate,
Unicode, finite-number and exact-integer rules.

Limits match the complete canonical top-level turn.failed.error object against
retained reviewed source. A message-only error requires no invented code field.
Plain text, model/tool/user quotations, generic exits, recovered failed turns
and unsourced provider wording cannot select a profile. The exact outside exit
and known zero survivors must appear in run observations. A matching provider
sample is only a candidate: every Codex signal additionally requires UsageWindows,
protected UsageWorker and UsageProfile mappings, actual Store.WorkerBinding and
ValidateUsageWindow and ValidateUsageSource. Exhaustion must be from the selected
profile, post-exit, at most 30 seconds old, finite and at least 100 percent, with
a known reset still in the future. Exact private service usage_raw TSV bytes and
the matching committed usage_window envelope are read back and pinned in
LimitSignal.UsageEvidence. Nil evidence cannot enable codex-file rotation.
The outside producer/normalizer owns its actual installed command and profile
mapping; this adapter invents no Codex usage command. Watchdog still owns
fresh eligibility, profile/model affinity and remaining-budget checks.
Structured stdout remains partial tool-call coverage; recognizing one record
does not prove that every call was captured.

Home and credential utilities run in the trusted outside data/credential
worker. Records and Leases live outside every lane mount; private modes alone
are not OS isolation. Create exclusively creates a home under an existing
private parent. A logical .codex descriptor remains separate from its opened
physical root. PreparedSession reloads the protected record. Environment
construction requires a separately verified absolute launch-namespace home
descriptor; it refuses an unresolved relative label and never merges the host
environment.

Audit checks protected roots, private owned ancestors, single-linked auth and
sealed config/hooks digests. Ordinary files, sockets, hardlinks and external or
dangling links are observations rather than a reason to block normal tools.
Selected seed assets exclude auth/history. Project checks inspect both
config.toml and hooks.json through the bounded physical materialization.
Redirection checks remain a blacklist, not a command or tool allowlist.

NewCredential requires an independently enrolled account SHA-256 obtained from
protected profile enrollment, never derived from incoming refresh bytes.
Install persists it; Refreshed consumes a received anonymous descriptor and,
like Matches, refuses another account. It never reopens the lane auth pathname
for returned bytes. The secrets
worker must additionally validate the actual provider exchange/token affinity.
A partial publication retains canonical-login leases and poisons reuse.
Quiesce requires the exact outside exited/zero-survivor observation.
BindCodexSession accepts only a trusted Service and outside CaptureRecord.
Failed binding/quiescence saves restore prior facts and poison reuse.

Revoke removes the native auth name before ancillary cleanup. Unexpected
entries remain observations; copied auth/transient files require actual login
rotation and retain the affected lease. Close refuses unresolved rotation.
Close/final-save failures poison reuse. Formatting and JSON redact credential
payloads; mapped errors preserve typed reasons without raw private paths.

Imported first-run provenance, explicit watchdog continuation selection and
unmapped-startup retry are still coordinated integration matters. In
particular, fix 9 permits start reservations only at run 1 and requires a
vendor ID for retained plans. The preserved local startup helper tests do not
authorize a new public retry mode or change the shared validators.

The shared fixture uses a valid hyphenated configuration name, complete reserved
pins and synthetic ticket/proof references. It calls the shared reservation
request, plan and binding validators. Agent bindings carry Kind=agent and the
reserved role/level, with correctly hashed records. These fixtures do not prove
real authority consumption or same-transaction helper_prepare persistence.

The Linux Go driver contains 190 controls in ordinary and laneboss_faults
builds, producing 380 red/candidate result rows. Its 77 fix-9 and 25 fix-10
literal controls plus 26 fix-11 and 20 fix-12 controls are retained in
launch_red.json; the original 42 remain. The separate
protocol driver has 23 controls and names every mutation before checking its
unique anchor and selected test. Static checks cannot replace those runs.
No synthetic unit receipt is authenticated provider, installed-service or OS
acceptance. The nine live CODEX assertions remain required.

The supplied ca1e78f Linux report failed race tests in both builds at the shared
reservation fixture, and therefore failed the Go red/candidate driver. Its
protocol tests and protocol reds passed. This candidate needs a fresh exact-source
Linux run; no runtime pass is inferred from the fixture correction or Mac static
checks. Pinned resume syntax and a real provider-limit sample remain unverified.

Fix 11 consumes typed materialization and outside usage ports; there is no
Codex-owned fix11_stubs.go. Actual store/service/secrets stubs keep their owning
not_implemented errors. TestDataOwnerRefusal, TestUsageOwnerRefusal and
TestUsageWorkerRefusal call actual owner packages. The brief reports the earlier
consumer landed after review and green boxes; this source needs a fresh Linux
race run, all 380 Go rows and 23 protocol rows. Static checks do not establish
those runtime results. The case reads stdout or vendor, matching the API.
