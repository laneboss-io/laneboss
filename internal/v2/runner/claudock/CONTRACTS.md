# Claudock integration contract note

This note describes the adapter against `v2.0-draft.4` fix 10 (`3803f4d`),
supplied in baseline `d205742` with the prior Claudock candidate `ba53c1e`.
It records dependencies and the outstanding framing clarification; it does not
introduce shared fields, methods or permissive defaults. Integration owns shared
amendments and assembly. [CONTRACT-GAPS.md](CONTRACT-GAPS.md) names the remaining
other-owner dependencies. No additional shared amendment or rebase is assumed.

`api.Runner` keeps its signatures. `Session.HistoryID` is now required to be a
valid ID equal to the request's private home history ID, including during
capture extraction. Changing both IDs still fails the existing protected
continuation binding. Adapter-version receipts and protected records use
`claudock-cli/v2.0-draft.4-fix10`; older generations require explicit recovery or
migration and are never overwritten as a compatibility shortcut.

The candidate pins Claudock 0.1.0 and Claude Code 2.1.296. Source and fixture
checks establish candidate behavior only. No authenticated vendor receipt,
production isolation pass or automatic profile-swap pass is claimed here.

Current installed planning uses the measured credential-selection, bootstrap
and helper-owned home bindings described in
[the native planning note](../../admin/CLAUDOCK-PLANNING.md). The version and
`auth status` probes establish the exact CLI's selected credential method;
provider authentication and authenticated two-turn behavior remain separate
acceptance evidence. The broader historical handoff requirements below do not
turn a synthetic key into provider authentication.

## Launch authority consumed by the adapter

`Start`, `Resume` and `Turn` first compare the entire request with the protected
durable life/run input. `SelectLaunch` supplies only the service scope and
reservation/effect/claim/helper-lease IDs from the current service job. It cannot
supply a path, plan, executable or successful authorization receipt. The adapter
then calls the real shared ports, independently reloading:

1. `StateStore.LaunchPlan` and `ValidateLaunchPlanRecord`, with exact installed
   config, service actor, reservation and target correlation;
2. the currently claimed `StateStore.Effect`, original causal actor/requester,
   operation/request, cancellation epoch and unexpired claim;
3. `StateStore.Policy`, `StateStore.Grants` and `GrantResolver.Resolve` for the
   retained reservation, rejecting changed policy, revocation, expiry,
   exclusions or narrowed grants without requiring the child lane projection
   that planning and preparation have yet to publish;
4. `LaunchSourceResolver.ResolveLaunchSources`, requiring the exact sourced
   enrollment/runtime generation, driver, backend and pinned wrapper identity;
5. `LaunchStorageResolver.ResolveLaunchStorage`, with the reserved helper lease,
   life-owned root/generation, workspace, private home and logical cwd;
6. original `launch_request` bytes through `ObjectMetadata`/`Blob`, verifying
   committed class, origin, config, operation and all byte ranges/hashes, then
   its request digest, method and authorized launch budget;
7. the previous `LaunchBinding` and its complete retained plan on resume/turn,
   using `ValidateLaunchBindingPlan` before comparing the same home/session and
   installed runtime; and the current service-origin prompt bytes for this run.

Stage 5 can consume a sourced record before a complete plan exists. Requiring
the finished RunnerPlan as its own prerequisite would create a cycle. Once the
complete plan exists, helper-resolved home/lease/workspace and the resulting
RunnerPlan must equal the retained plan. The private service Records also seal
the request/reservation/inputs/storage digest under the reservation ID. Identical
retries replay; changed inputs refuse after service reconstruction.

`PrivateHome.VendorDirectory` is the relative `.claude` required by fix 9.
`PrivateHomeBinding.RootID` resolves through the helper-owned opened storage
registry, with life and generation checks; it is not a directory or blob name.
Local embedding passes that verified binding to `HomePath`. Installed planning
uses `PlanHome` in the helper credential worker and returns no host path or
protected record descriptor to the event service. The actual Linux projection and
settings argv use `/home/lane/.claude`. The helper owns physical resolution and
must independently reject aliases, overlaps, escapes and lost journal entries.
No lane-supplied path is opened to establish launch authority.

## Fix 10 child pins and capture refusal

Level, Role, Driver and consumed Authority come from the retained reservation.
RunnerRequest contains no child level/role; neither its caller nor the service
scope can supply those pins. Start compares the original retained start's
level/role/driver with the reservation and requires the reserved Claudock driver.
The current enrolled runtime must have that driver. Resume/Turn preserve the
previous reservation's level/role; its validated plan, unchanged enrolled runtime
and current reservation preserve the driver. Shared ValidateLaunchBindingPlan
checks the actual prepared agent kind, child actor level/role, committed record
digest and complete recovery. The full reservation, including Authority, stays
in the retained planning result and private input seal. No new consumed ticket,
proof or starter identity is issued by the adapter.

Capture refusal is default-false protected policy. A refused binding needs
RefusalPolicy.Allowed, PolicyGeneration and ApprovalID; its plan additionally
retains CapturePolicy at the reservation's generation. The adapter calls
ValidateCapturePolicy against a fresh StateStore.Policy read, rather than using
the binding or plan snapshot to enable the exception. Disabled/stale policy,
missing or changed approval and missing metadata refuse. The input seal also
retains the current refusal flag/generation/approval, so same-reservation replay
cannot discard a changed policy input. The publisher/store must authenticate
actual consumed D6 approval and current revocation; ID-shaped fixture metadata
does not establish that authority.

A valid exception permits only the visible incomplete isolated Start plan.
Resume/Turn refuse when their prior recovery capture or retained current plan
has refused capture. Session and limit extraction validate prepared identity and
current policy before propagating the owning refusal; an allowed refusal never
becomes primary bytes or a continuation signal. Registered capture requires no
refusal exception or approval metadata.

Stage 5 still consumes sourced records before capture registration and Prepare;
it cannot require its future prepared binding. Complete capture extraction and
restart require the retained plan and agent binding; an existing binding without
its plan does not activate a legacy fallback. The fix 10 unconditional
helper_prepare transaction gate belongs to lifecycle/store/identity, which must
atomically retain the bound plan, recovery, ready Lane and events even when an
attempt omits LaunchPlans. This adapter writes none of those transactions.

## Required capture-framing decision

`api.Runner` receives one `CaptureRecord` per extraction call. This adapter's
`Capture` dependency resolves its exact canonical metadata and immutable primary
bytes; those bytes must contain complete vendor JSONL records. A pipe read may
end inside a JSON string, while another read completes it. Such arbitrary chunks
cannot each be decoded as complete records. The current adapter refuses split
or malformed input rather than discarding it, classifying a fragment or guessing
that the remaining stream is clean.

Integration/lifecycle must choose and document one of these approaches:

| Approach | Required producer and consumer behavior |
| --- | --- |
| Canonical complete-frame spans | The outside spool retains the exact bytes and assigns honest IDs, stream offsets, hashes, coverage and observation times to complete frames/spans. Lifecycle passes those canonical records to the runner. Raw chunks and their original evidence remain retained. |
| Shared multi-record span contract | Integration amends the API to identify all constituent captures and their exact byte ranges, gaps and coverage. Both runner adapters and watchdog validate and retain that provenance before extracting sessions or limits. |

Consumers are lifecycle, Claudock, Codex and watchdog; capture storage and event
views must preserve the selected representation. Concatenating chunk bytes under
an unrelated existing capture ID/hash or calling a cut/gapped chunk complete is
invalid. The pending amendment must define frame boundaries and exact source
ranges, including newline bytes, before the full capture gate can pass. No
assumed span field or lane-authored replacement is used in this package.

## Trusted bindings required by assembly

These bindings already exist in the trusted `Dependencies` struct. They are
composition dependencies, not proposed lane-facing RPCs. Missing required
bindings return typed `not_implemented`; an error from a supplied binding
propagates with its typed refusal/Instead route intact.

| Binding and consumers | Required evidence or operation |
| --- | --- |
| Installed artifacts and runtime manifest; packaging, launcher, both runners | Retain and hash the wrapper and actual companion executable. Mount the checked bytes read-only at their planned paths and pin Claude's actual PATH lookup. Rehashing the wrapper alone is insufficient. |
| `Config`, `SelectLaunch`, `State`, `Sources`, `Storage`, `Grants`; service, lifecycle, admin, grants | Install real config-bound typed ports. Reload current effect authority, sourced enrollment, policy/grants, original bytes and helper storage as described above. Retained IDs alone are not authority. Each unavailable owner method's typed refusal propagates unchanged. |
| `Run` and `HomePath`; lifecycle, credential worker, runners | Resolve the durable life/run, logical turn, home/history, session/cwd, model and slot mapping after service reconstruction. Resolve the verified PrivateHomeBinding through the helper's actual storage registry, never caller strings or a pre-resolved path fixture. |
| `Profile`; secrets, lifecycle | Correlate delegated profile/provider/expiry with the canonical-login lease and current grant. A profile label is not injection or refresh ownership. |
| `VerifySlot(ctx, request, requiredUmask)`; secrets, lifecycle, launcher | Validate actual slot/token injection, one-profile projection, refresh ownership, minimal environment, pinned companion lookup and protected mounts/settings. Require measured or pinned helper bootstrap proof that the vendor is exec'd with **umask 077**. A service-process umask, callback that assumes 077, or post-run chmod is insufficient. Missing proof refuses before producing argv. Retain that bootstrap evidence and check the first actual transcript is regular, single-link and mode 0600 through the installed CLI's confined probe. |
| `VerifyMode`; packaging, secrets, launcher, runner | Require the installed vendor's measured version and credential-selection output with both exact executable pins. The helper separately measures native bootstrap/home confinement and protects generated settings. Authentication, refresh and structured-record acceptance require their own authorized live gates. |
| `Capture`; lifecycle, runners, watchdog | Read exact immutable primary bytes and metadata from the outside spool, with the agreed framing and complete coverage. Verify size/hash; a caller setting `Primary` is insufficient. |
| `CaptureControl`; admin/helper, lifecycle, runners | Reconcile the exact registered producer kernel generation/boot and pipe IDs from the opened plan, complete LaunchBinding recovery and CaptureState. Accept only registered stream IDs and acknowledged byte ranges with service-origin object provenance. An explicit refused binding propagates its owning error; absent/unbound/supplementary evidence cannot establish a session or limit. |
| `Observation`; lifecycle, runner, secrets, watchdog | Return the retained outside observation for the actual life/run, process ID, containment and generation, with known termination and zero survivors. Match it to the prepared/released process record. |
| `UsageWindows`, `UsageWorker`, `UsageProfile`, `State.WorkerBinding`; secrets, identity, service, packaging | Supply the fix 11 outside UsageWindowSource result for the causing opened launch and delegated **from-profile**. Resolve real installed/native producer facts and protected profile enrollment. Validate the shared fresh post-exit exhaustion envelope and exact pinned usage TSV bytes, then read back its private committed usage_window object by evidence ID. The actual BlobRef becomes LimitSignal.UsageEvidence. Keep usage_raw and usage_window private, service-origin and bound to the causing operation/life. Missing support retains its typed owner failure; Room.Available is no longer an exhaustion input. |
| `LimitGuard`; lifecycle, runners, watchdog | Corroborate every stream and auth, guard and provider-affinity receipt. Missing whole-run coverage refuses even after valid outside usage. A lane can print a vendor-shaped quota envelope into a primary pipe, so captured text cannot replace outside usage. |
| `ReportHome`; lifecycle, runner | Retain ordinary-tool findings without treating sockets/links outside library-owned paths as a failed owned-entry audit. Screen names before wider publication. |

`RunnerPlan` contains one executable identity; the second executable pin and
fresh environment values therefore remain launcher/runtime-manifest
responsibilities. The prompt BlobRef must reach standard input byte for byte.
Do not place prompt text or credential values in argv, event payloads, copied
fixture homes or archived environment snapshots.

## Credential worker and private-home lifecycle

The worker must access the selected private home and protected `Records` without
mounting those records into any lane or granting the event service broader
filesystem authority. Home paths and records must not overlap. The actual
UID/mount/helper arrangement must prove this access with the existing private
modes; a path-separation check is only one prerequisite. If that arrangement
cannot work, the credential mode stays unavailable.

Every worker using a canonical login must share the same protected flock domain.
Different record roots do not serialize independent copies of the same login.
The home controller retains its lease until `Close`, including after `Revoke`.
`Seed` must run before opening that controller or after closing it; it acquires
the identical home-identity lease and never rewrites a controller-owned
generation. Retained credential-container handles must match their current
paths for install/token/reserve operations. Revocation deliberately collects
through the retained handles even after a rename and marks possible copies for
credential rotation before releasing login ownership.

`Slot.Quiesce` checks the frozen terminal record's shape and reserved life/run.
It does not independently observe the kernel or bind a process generation at
`Reserve`. The trusted credential/lifecycle worker must supply the canonical
observation for that reservation and reject stale or forged handles before
calling it. Syntactically valid caller data, service reconstruction or release
of a crashed worker's flock cannot establish that the old process stopped.
Unknown observation retains ownership; lifecycle reconciles it before reuse.

The d4fix1 private record also retains generated directory names, including
empty imported directories. Recursive vendor checks reject links, shared modes
and unrecorded configuration assets. Earlier private record generations remain
preserved and require an explicit migration, rather than receiving default
directory authority. New requires the whole-run LimitGuard callback at
construction; that callback must still return a failing typed result when its
actual run coverage is unavailable.

Generated settings and hooks have protected digests. Plans disable other Claude
settings sources and load only the explicit generated settings projection.
The pinned argv additionally requires `--permission-mode bypassPermissions`.
The source is `docs/claudock.md:403–406`: headless default denies approval-based
tools; bypassPermissions permits their execution within the mandatory outer OS
boundary. The live case requires an actual vendor tool call to write fresh
unpredictable workspace bytes and independently checks the bytes through
`grants test-child`. A model's claim of success is not this observation.
The pinned live compatibility gate must prove these semantics against conflicting
project/local settings. Headless token injection does not establish safe file
login refresh or authorize a host Keychain lookup.

## Unavailable modes and acceptance handoff

Linux `claudock-headless` and `claude-api-key` planning/projection are implemented.
`VerifyMode` and `VerifySlot` must still refuse unavailable or unproved runtime
conditions. Helper, API and native Darwin planning remain typed
`not_implemented`. Separate live evidence is required to enable each mode;
neither a subscription refusal nor a fixture pass authorizes a paid fallback.

Watchdog owns fresh room evidence, same-provider eligibility, remaining budget,
manual-control serialization and the actual continuation. This runner emits a
candidate limit signal only after capture, whole-run refusal and exact exited
process checks. It does not perform a swap, change task retry counters, reset a
budget or acknowledge mail.

The Linux supervisor must run the current unit/mutation commands and then the
installed `CLAUDOCK-TWO-TURN` case with independently prepared delegated inputs.
New unit controls remain unverified until that run. Pre-draft.4 box results do
not validate this port. All three independent live credential-mode cells and
the capture-framing gate remain incomplete. The case uses an authentic parent
lane endpoint, retained mutation keys, the typed initial streaming response,
the complete ProfileSwap fences and helper-measured ReleaseReceipts. It never
uses a human dashboard method without a real connection-bound read session.
