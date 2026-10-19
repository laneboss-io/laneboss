# Claudock v2 adapter

This package implements `api.Runner` as a plan/capture adapter. It never starts
a process, runs repository code, fetches a secret, signs in, changes a paid
provider, chooses another profile or releases an isolation gate. Lifecycle,
the credential worker and the OS launcher retain those responsibilities.
It imports no legacy `runnerhome` code and changes no frozen API type.

[CONTRACTS.md](CONTRACTS.md) tracks the integration requirements and pending
capture-framing clarification. The supervisor supplied fix 10 (`3803f4d`) in
baseline `d205742`, retaining the prior `ba53c1e` adapter. Other-owner needs
are listed in [CONTRACT-GAPS.md](CONTRACT-GAPS.md).

Draft.4 makes `Session.HistoryID` explicit. Every planning/capture entry checks
that it is a valid ID equal to `PrivateHome.HistoryID`. The protected home
binding still rejects a continuation that changes both IDs together. The
adapter version is `claudock-cli/v2.0-draft.4-fix12`; older protected generations are
preserved and refused, not silently relabeled or overwritten.

The candidate vendor contract is Claudock **0.1.0** and Claude Code **2.1.296**.
The source references are `docs/claudock.md`, its pinned Claudock source
`d43cf40033f8`, and the documented native Claude formatter locators. These are
static sources, not live authentication evidence. Both executables are pinned
by ID/version/SHA-256; their actual bytes are rehashed for every plan. Another
version returns a typed `not_implemented` error pending its own adapter review.

Linux `claudock-headless` and `claude-api-key` have plan/projection code. The
installed `VerifyMode` measures the enrolled Claude Code binary's `--version`
and `auth status --json` in a fresh private home with synthetic credential
input. It requires the selected first-party credential method and rehashes both
installed executable pins. This proves credential selection, not valid provider
authentication, a model response or subscription refresh. Enrollment labels
and fixture receipts alone cannot enable a mode. The helper separately measures
the actual bootstrap and performs the private-home transaction as described in
[the native planning note](../../admin/CLAUDOCK-PLANNING.md).
`claudock-helper`, `claudock-api` and native Darwin planning return typed
`not_implemented` errors. The wave-0 subscription file-login mode is not a
frozen v2 mode and is not silently relabeled as headless. No paid fallback or
host Keychain path exists here.

## Trusted composition bindings

`New(Dependencies{})` fails. Assembly must bind one adapter instance to one
configuration and supply the following service-owned dependencies. None is a
lane-facing RPC or authority inferred from a caller's label.

| Binding | Required meaning |
| --- | --- |
| `Config`, `SelectLaunch`, `State`, `Sources`, `Storage`, `Grants` | Current installed service scope and selector-only planning job; real StateStore, LaunchSourceResolver, LaunchStorageResolver and GrantResolver ports. Re-read the retained reservation/effect claim, current policy/grants, original bytes, enrollment and helper-owned storage. Missing implementations keep their typed owner errors. |
| `Executable`, `ExecutablePath`, `Claude`, `ClaudePath` | The two installed, retained immutable artifacts. Mount their actual bytes at the same absolute paths. Pin the companion Claude binary in the launcher's runtime manifest as well as the wrapper. |
| `Records` | A private directory absent from every lane mount. Local embedding uses its service UID; installed home transactions use the root helper's private record directory. It holds home device/inode records, generated-file digests, session/home/model bindings, permanent kernel lock files and rotation markers. |
| `Run` | Read the exact durable `RunnerRequest` for the requested life **and run**. It must preserve logical turn, private home/history, vendor session, cwd, model and credential lease mapping across service reconstruction. |
| `HomePath` | Resolve the verified PrivateHomeBinding through the helper's actual RootID/life/generation registry outside checkouts. PrivateHome.VendorDirectory is relative `.claude`; the Linux runtime projection remains `/home/lane/.claude`. Neither label is host-path authority. |
| `PlanHome` | Installed alternative to `HomePath`. Run the identical home audit, conversation check and atomic seal in the helper credential worker, using protected request bytes and allocation selectors. Return no physical path or record descriptor to the service or lane. |
| `Profile` | Resolve a current delegated profile grant, including provider affinity and expiry, from the slot's opaque grant/profile handles. |
| `VerifyMode` | Measure the installed vendor's declared version and selected credential method independently of enrollment labels. Missing, wrong-version, wrong-digest or wrong-mode evidence returns a typed failing result. |
| `VerifySlot` | Check actual slot/token/lease, refresh owner, protected mounts/settings, minimal environment, companion lookup and grants. Its requiredUmask argument is 077; independently require measured or pinned helper bootstrap proof of that vendor exec umask. No service-global umask change or assumed constant proof is valid. |
| `Capture` | Read canonical metadata and exact immutable primary captured bytes by capture ID, from the outside spool. A lane-authored file or `Primary=true` in an argument is insufficient. |
| `CaptureControl` | Reconcile the registered producer/kernel/boot/pipes from the opened plan, CaptureState and LaunchBinding recovery. Only durably acknowledged registered streams and service-origin capture bytes can establish a session or limit. Refused/unbound/supplementary evidence fails. |
| `Observation` | Read the outside supervisor's retained process observation for the same life/run, with known exit and zero survivors. |
| `UsageWindows` | Read the real outside worker's normalized result for the causing opened launch, operation, delegated from-profile, provider, actual run end and pinned adapter, executable and runtime. Require successful post-exit exhaustion observed within 30 seconds and validate the exact pinned five-column TSV source. Missing support returns the secrets owner's typed failure. |
| `UsageWorker`, `State.WorkerBinding` | Resolve the actual installed endpoint and native peer for the outside usage lease, then independently authenticate the current worker principal, claim, generation and boot through the protected store. Evidence fields are comparison claims, never native authority. |
| `UsageProfile` | Read the vendor profile spelling from protected delegated-profile enrollment. Never derive it from an envelope or TSV row. Raw names remain in private source bytes. |
| `LimitGuard` | Corroborate all run streams and auth, guard and provider-affinity receipts. Outside exhaustion is validated separately; missing whole-run coverage still refuses. |
| `ReportHome` | Retain nonfatal ordinary-tool findings. Screen relative names before exposing them beyond protected evidence. |

All dependency failures propagate as typed errors. An existing typed refusal
and its Instead route remain intact, including wrapped constant causes. Raw
filesystem/parser/provider errors are mapped to screened constant diagnostics.
No default callback returns a permissive empty success.

Start now publishes its binding and reservation seal in one record transaction
under the per-home flock. That transaction refuses a foreign reservation ID
after a seal exists and refuses changed inputs for the same ID. A failed
publication leaves neither binding nor seal; the original reservation can
retry or replay with identical Session, Home and Model. The continuation and
adoption unavailable barriers are unchanged.

The seal/start regressions use the actual adapter and record publisher. One
makes a real temporary-file open fail, checks the absence of a partial binding,
then retries. Others refuse changed binding fields and a second reservation,
with and without conversation history. TestConcurrentStarts runs overlapping
Start calls with separate Records handles and independently claimed selectors.
Both finish stale preflight before either commits; the first publisher is
parked while the other handle proves the record flock is held. Exactly one
plan and one seal may remain. Removing the foreign-seal refusal targets that
specific assertion. Store CAS reachability and the in-process race canary still
require Linux execution; static checks prove neither.

Before emitting a limit, the adapter reads both private service-origin usage
objects under the causing operation and life. UsageWindowEvidence.ID selects
the committed usage_window object; its exact decoded bytes must equal the
source result. The signal's UsageEvidence is that object's actual BlobRef.
The raw object has class usage_raw, a bounded exact hash and the selected TSV
row. Room.Available is no longer an exhaustion input. Missing usage bindings
may leave planning available, but always stop limit classification. The five
f11-usage controls isolate percent, freshness, from-profile, producer and source;
other controls cover private retention, actual end, TSV and dependency errors.
These use private synthetic worker fixtures, not authenticated usage evidence.

Fix 10 reads child Level/Role/Driver and consumed Authority from the reservation,
then checks original start intent, current enrollment and previous continuation
binding against those pins. The planning result and private seal retain them.
Prepared recovery requires Kind=agent and a matching actor level/role, record
digest and plan; there is no legacy-kind or missing-plan success path. The
adapter creates no child authority or helper_prepare transaction.

Refused capture requires the plan's policy snapshot plus explicit allowed,
generation and approval metadata matching a fresh protected current policy.
StateStore.Policy's publisher must validate the actual consumed D6 approval and
revocation. The adapter never enables the exception from request metadata or a
plan snapshot alone. Current refusal policy inputs are sealed for replay.
Allowed refused capture may produce only the incomplete isolated Start plan;
prior/current refused capture blocks Resume/Turn, sessions and limit signals.
Registered capture remains usable with the default-false policy. Stage 5 can
still build from sourced inputs before capture registration and Prepare.

Home/slot filesystem operations need the authorized credential/helper execution
context and actual access to the selected private home plus protected records.
The Linux UID/mount arrangement must prove that access in its live gate. Do not
grant the primary event service broader filesystem authority, weaken private
modes or mount the record store in a lane to make these checks succeed. If the
worker/projection arrangement cannot provide it, keep the mode unavailable.
All workers sharing a canonical login must use the same protected lock domain;
separate record directories cannot serialize copies of the same login.

The launcher delivers the retained `RunnerPlan.Prompt` bytes on standard input.
The prompt is never argv text. Headless plan argv uses the private projected alias:

```text
claudock run claude -- -p --permission-mode bypassPermissions
  --setting-sources "" --settings SETTINGS
  --session-id UUID --model MODEL --effort EFFORT
  --output-format stream-json --verbose
```

Resume and turn replace `--session-id` with `--resume`. The empty settings-source
argument is a literal empty argv element, disabling writable user/project/local
settings; only the explicit generated settings projection is loaded. The pinned
live mode receipt must prove that behavior, including a conflicting project
settings control. The model/effort are explicit inputs, never aliases chosen
by this package. The inner sandbox is disabled in the generated settings;
the outer gate must succeed before any plan is executed.
`docs/claudock.md:403–406` documents the pinned permission flag: headless default
denies tools that require approval. The real CLI case now requires a captured
vendor tool write and an independent confined read of unpredictable workspace
bytes. Strict vendor/history file modes remain in force; VerifySlot requires
helper-established umask 077 and the live probe checks the first transcript's
actual regular-file type, 0600 mode and single link after run 1.

`EnvironmentNames` contains names only. The credential/launch workers construct
fresh values: private HOME/XDG/temp paths, private Claude/Claudock selectors, a
PATH whose Claude lookup is pinned, and only the selected slot credential. Do not
merge ambient environment values or place a token in `RunnerPlan`. Claudock's
private registry contains exactly one `claude` alias pointing to the logical
private vendor directory. Its actual delegated profile stays in the slot and
protected service records. The wrapper store is explicitly empty in headless mode.

API key mode binds a new home to `claude-api-key`, adds exactly one managed
`apiKey` profile named `lane-key`, and selects it with `claudock run lane-key`.
Claudock also requires the original default subscription entry; it is retained
without changing its credential behavior. The mode cannot change after binding.
Both registry and executable preferences remain protected generated projections.

The API key slot now projects a private 0600 store at
`.config/claudock/key-store.json`, using the vendor's version 1 `items` format
and directory-derived credential service. The helper checks its single link,
owner and read-only namespace view. It exports a separate sealed copy to the
final unprivileged receiver, which extracts only the selected key for the
existing `ANTHROPIC_API_KEY` environment contract. Claudock clears inherited
credentials and reads that same selected store. Withdrawal removes the tracked
store inode before the unchanged complete release scan. No key enters argv,
generated records, capture metadata or logs.

The shared projection contract in `api/credential_validation.go` changes from
`item.Delivery, item.FileMode = "env", 0` to
`item.RelativePath = ".config/claudock/key-store.json"`, retaining the initial
`Delivery: "file", FileMode: 0600` and `ANTHROPIC_API_KEY` name. The environment
timing, reserved-name, ownership and read-only checks remain required.
The launcher sets `CLAUDOCK_REGISTRY_DIR` and a `file:` credential-store path
under the lane home explicitly; no platform default or personal store is used.

The `laneboss_vendor` test verifies and extracts the pinned public Claudock
0.1.0 release and installs Claude Code 2.1.296 in a disposable Linux test home.
Its generated fake key must reach a real provider authentication error in
stream JSON. The twin selects an actual subscription-kind profile under the
API key mode; V2 rejects its shape and a direct vendor attempt must fail with
no API key selected. Synthetic planning
authority and a test namespace surround these real vendors; this is credential
plumbing evidence, not authenticated service or complete installed-lane evidence.

## Ported home and slot behavior

`CreateHome(path, records)` creates a new private skeleton without importing
human state. `OpenHome` verifies its physical identity and protected generation.
The parent must already be private. The record store cannot be nested in the
home or contain it. The launcher must independently keep it outside **all**
lane mounts, including broader parent mounts. A path check is not OS isolation. Session and driver authority
never reside in a lane-writable marker or conversation-binding file.

`AuditOwned` checks only library-owned runtime/auth/registry/generated paths,
with Lstat on every intermediate component, expected types, single regular-file
links and private modes. It checks the supplied open root against Lstat(path).
The managed `.claude` tree is checked recursively, including history, sessions,
projects, caches and every created vendor subdirectory. Hooks, plugins, agents
and skills must contain only files and directories recorded by protected
seeding; ordinary private vendor runtime data remains writable. Conversation
lookup independently bounds and checks its complete project tree before opening
the selected private, single-link transcript. A symlink cannot hide a shared
project directory from an otherwise successful start.
`Inspect` reports ordinary venv links, browser locks, sockets and Git/rustup
hardlinks; those do not refuse another turn. Required conversation lookup still
refuses missing/ambiguous/linked history instead of starting a replacement.

`Seed` copies explicitly supplied generated assets, refuses runtime/auth/history
destinations and links, records exact digests outside the home, and makes copied
files read-only. A failed publication marks the protected generation incomplete
before changing destinations. Protected records retain generated directories,
including empty ones, so missing approved directories and unrecorded additions
are detected. Replacing a file by rename despite its mode is
detected at the next plan. Source mutation cannot change the independent copy.
Seeding acquires the same home-identity lease as `NewSlot`; even an idle
controller must be closed before a generated asset is imported. Refusal leaves
the existing bytes and protected generation unchanged.

`NewSlot`, `Install`, `Token`, `Reserve`, `Quiesce`, `Revoke` and `Close` are
credential-worker utilities. The canonical login handle, rather than its profile
alias, owns a kernel flock through exit/quiescence. Reconstruction does not prove
that an old runner stopped; lifecycle must reconcile it first. Partial swaps
poison the slot and retain both login leases until credential removal succeeds.
Headless tokens do not enable an unverified subscription-file refresh import.
Token handoff, installation and reservation also compare each retained
credential-directory handle with its current path. Identical copied bytes in
a replacement directory cannot satisfy that identity check. Revocation keeps
using the retained handles so this check cannot block credential collection.

`Quiesce` validates the complete terminal record shape: life/run and process
identities, UTC time, prompt-status enum, known zero survivors and exactly one
int32 exit code or positive signal. The trusted lifecycle/credential worker must
still corroborate the canonical process and generation; record syntax alone
cannot prove that an OS process stopped. Limit classification shares these
shape checks and additionally requires the exact retained exit observation and
an exit code; signal termination cannot authorize quota continuation.

Revocation first removes auth/registry/store/token names using retained directory
handles. A renamed container cannot hide the original name. A hardlinked
credential's local name is removed, its surviving copy is reported, and the
canonical login is durably marked for rotation before its lease is released.
That marker blocks reuse through aliases; clearing it requires the credential
owner's validated rotation/recovery workflow, which this package does not invent.
Records-root checks, lease acquisition and rotation reads/writes share the mutex
used by Records.Close. Closed or replaced records return a typed error after
known credential names are removed; canonical ownership remains held. Pending
rotation is retained across retries in the same controller. A post-acquisition
rotation refusal closes only its newly acquired login lease before publication
and leaves neither that lease nor a map entry behind. Service reconstruction
still requires durable outside reconciliation before reusing any login.
Only regular `.runnerhome-*` temporary files are then removed. Unexpected
runtime entries remain reported and cannot block removal of known credentials.
Actual removal failures retain ownership. Close finishes other handle/lease
cleanup after a close-result failure.

## Capture and quota scope

Session extraction accepts a top-level structured vendor init with the exact
bound UUID/cwd. Limit extraction accepts only supported provider error envelopes
with session attribution, canonical primary metadata, complete capture coverage,
matching byte length/hash and the exact retained exited process observation.
User/tool/ordinary assistant quotes, successful results, bare exit codes,
stderr wording, auth and guard errors cannot trigger a swap. A conflicting
refusal suppresses quota evidence. Malformed/duplicate-key/oversized/cut data
fails explicitly. Signals carry the full capture ID/hash and real exit code;
no diagnostic excerpt or credential value is copied into them.

Fix 9 also requires a registered producer binding in an opened retained plan,
full identity recovery, registered stream/range acknowledgement and protected
object provenance. Optional structured capture is named `vendor` by the shared
contract. Each dependency is called through its real typed port. A genuine pipe
can still contain a lane-local process's forged envelope, so outside usage for
the causing profile is a separate requirement; a source-profile Available=false
result alone never proves exhaustion. LP-CAPTURE-IO-1 still needs to freeze the
actual outside vendor window schema and source provenance for LimitGuard.

The supported parser input is a canonical BlobRef containing whole vendor JSONL
records. Raw arbitrary pipe chunks may split a JSON value across CaptureRecords;
this adapter currently refuses such input rather than guessing or dropping it.
Integration/lifecycle must either retain canonical complete-frame spans with
their own honest IDs/offsets/hashes, or amend the frozen capture interface to
represent multi-record spans. The latter affects both runners and watchdog.
This is a required framing clarification before full capture acceptance, not
permission to change the meaning of coverage or hash concatenated bytes under
an unrelated capture ID.

The watchdog still needs fresh outside room/usage evidence and delegated
same-provider eligibility before it can swap. This adapter never performs a
swap, resets a budget, increments failure/retry counters or acknowledges mail.

## Review findings and verification

The H1–H6 follow-up findings were suspected from source; the implementation does
not claim an observed production exploit. Regression tests exercise the changed
filesystem behavior with synthetic canaries and positive controls:

| Finding | Regression behavior |
| --- | --- |
| H1 | Ordinary tool state reports without refusal; owned symlinks/hardlinks/modes still fail, including internal intermediate aliases. |
| H2 | Records survive rename/reopen outside the home; replacing settings/hooks fails their protected digests; continuation cannot change model/home/history/cwd/session; plans disable other settings sources. |
| H3 | Junk cannot prevent known credential removal; hardlink copies force rotation; renamed credential containers are collected through retained handles. |
| H4 | Shared parents fail before mutation; mismatched open roots fail; a close-result fault still releases the home lease. Go 1.26's Root.Close hides close errno, so the last row is an explicit unit fault after a real close, not a fabricated kernel errno. |
| H5 | Typed errors and constant wrapped reasons survive dependency mapping. |
| H6 | Synthetic credential bytes are built at runtime; names/literals stay short; partial-swap lease tests have no Linux-only build tag. |

On the authorized Ubuntu 24.04 test box:

```sh
go test -race -count=1 ./internal/v2/runner/claudock/...
go test -race -count=1 -tags laneboss_faults ./internal/v2/runner/claudock/...
python3 e2e/v2/cases/claudock/mutations.py \
  --source "$PWD" --evidence /test/evidence/lb-v2-claudock-unit-red
```

The test fixture explicitly sets its new temporary directory to 0700 and checks
its actual directory type and owner. It does not depend on the login user's
umask. Separate negative tests keep group/world-accessible records/home parents,
regular-file parents and linked records directories refused by production code.
No production privacy condition is skipped or relaxed.

The mutation runner first requires the candidate suite to pass with and without
`laneboss_faults`, each under child-process umasks 022 and 077. It then retains
source inputs, test executable bytes/digests, commands and exact exits/output
for 80 isolated Go red controls, followed by the same candidate matrix.
The two directory-privacy mutations remove only the production permission test;
the negative tests must then detect the incorrectly accepted input. A build,
fixture or unrelated assertion failure is not a killed mutation. Umask is set
only on the test subprocess; no production flag or environment bypass exists.
The four additional controls remove only retained-container identity checks,
restore the incomplete terminal-record guard separately for slot release and
quota classification, or put seeding in a different home lock domain. They
must reach their named token/quiescence/quota/seeding
assertions. The partial-swap test closes a real registry handle during
publication, after the token write, to exercise an actual failed write while
both login leases are held. It is a private unit fault, not a production
credential-mode switch or a fabricated kernel error.
The runner starts
no vendor, service, paid request or test machine. It must not run on the local
authoring Mac. Unit/fixture success proves wiring and regression behavior only;
the separate live CLI case is the authenticated/OS acceptance gate.

The added history mutation removes only the draft.4 session/home history-ID
condition. Its first invalid start must then reach the named failed assertion;
the valid control retains the exact history identity. The existing protected
history-drift test changes both IDs together, keeping the input internally
consistent so the stored binding remains exercised.

The same runner executes a separate 20-test Python consumer suite before
and after 24 case mutations. These test retained CLI keys/binding, typed
Health output, initial streaming snapshots and real stream ends, measured helper
release counts and continuation state. Each red must compile and reach its
named failed assertion; source bytes, interpreter bytes/hash, argv and exits
are retained. Mocked subprocess responses exist only in the consumer unit test;
the live case always invokes the installed CLI and actual service.

The d4fix1 review controls cover recursive vendor isolation and generated-directory
provenance, private conversation trees, rejected-login lease cleanup, closed or
changed Records, pending rotation across retry, the global inspection bound and
constructor dependency completeness. Quota controls use the pinned documented
`result` string / `errors` array shapes with a valid session ID, including an
absent or success subtype on an error result. A successful terminal result
suppresses earlier rate notices; auth markers, other subtypes, non-quota strings
and allowed rate warnings have distinct deciding mutations. These static-format
fixtures are sourced from docs/claudock.md and the retained profile_swap reader,
not presented as authenticated captures.

The fix 9 fixture persists original frames, grants/policy, current effect claims,
enrollment, storage registry identities, runner inputs, recovery, capture journals
and usage bytes separately. The adapter resolves them by selectors and uses the
real shared validators. It runs no vendor and supplies no production kernel or
authentication attestation. New red controls remove the specific reservation,
claim/epoch, policy/grant, runtime/storage, prompt, replay/recovery, capture and
outside-usage fences. Every red requires its own named assertion; the four
previous generic wantCode mutation messages are now specific to their sites.

Fix 10 adds 15 deciding Go controls and 11 consumer tests for reserved pins and
retention, current D6 policy/metadata/snapshot, replay, unavailable policy ports,
refused continuation and prepared identity. Rehashed negative identity records
keep the digest valid while changing only kind or actor pins. All controls
must compile and reach the named assertion; runtime evidence remains required.

All new runtime red/green, authenticated tool/umask and raw-pipe forgery results
remain supervisor-run Linux gates. The supervisor reports the `ba53c1e` fix 9
candidate GREEN on Linux; that result does not cover this working diff or live
authentication. Adoption and automatic Continue input recovery, public run-0
read semantics and the exact source-usage/live-forgery handoff are listed in
CONTRACT-GAPS; no automatic profile-swap acceptance is claimed.
