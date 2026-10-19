Static R9 audit of the supplied `267e25ca` tree and retained R8 report; no installed execution or runtime refusal was measured.  
Catalog Claudock start/running/events are 44/45/46, matching the brief's aliases 42/43/44; Codex start is 68 (`scripts/v2-serve/lifecycle.py:25`).  
The default installer does not supply the native credential peers required by agent prepare (`internal/v2/admin/credwire_linux.go:443`).  
After a successful credential-bearing stop, archive rejects the retained revoked lease; fixture output also prevents clean completion (`internal/v2/admin/arch_fs_linux.go:358`, `internal/v2/dataworker/cleanup.go:167`).  
Capture lifetime, Go task ceilings, expired prepare-child ownership and monitor timing remain **suspect** until exercised under the installed units.  
The tables give phase order, exact sites, conditions, smallest repairs and owners through cleanup 78; all work in this round is documents and retained source evidence.

# Installed graph and verdict scope

The source revision comes from the brief; it was not queried through Git.
The installed lifecycle build selects `laneboss_partial` and
`laneboss_e2e_authenticator` at `scripts/v2-serve/run.py:810`. Its fixture
runner is selected at `internal/v2/assembly/runners_partial.go:16`, and the
case requires both actual contained L5 roots (`e2e/v2/cases/serve/STEPS.md:3`).
The stand-in replaces the vendor executable. Native helper, identity, store,
outbox, capture and collection remain on the installed graph. Neither this
audit nor that fixture is an authenticated AI-service test.

The current capture-allocation refusal at
`internal/v2/admin/launch_capture.go:118` is the brief's serve2b round-20
work. The ranking below assumes that prerequisite has been repaired and its
actual storage journal survives materialization. It is not counted again.

**Will refuse** means that the cited code rejects the stated source-derived
condition on the default installed fixture, or on an explicitly identified
optional input branch. It is a prediction, not a new observed refusal.
**Suspect** means that task counts, scheduling, elapsed time or native state
determine whether the failing condition occurs. Later sites assume the
preceding gates succeed. Two consumers of the same stopped-lease semantics
are separate sites, not separate root-cause projects.

The literal catalog order comes from `scripts/v2-serve/lifecycle.py:25`:
Claudock inputs / start / running / events / reason / stop / quiescent / abandon / archive / 
clean/collected are 43–53; Codex human/proof and input rows are 54–67;
Codex start through collected are 68–77; final cleanup is 78. The loop
finishes Claudock archive/clean before it starts Codex
(`scripts/v2-serve/lifecycle.py:238`). Interactive `lane.input` has no
catalog row; it is audited separately below.

## First scheduled sites, in path order

Sites 1–8 are the eight sites in the short report. Sites 9–10 continue the
same scheduled path. The early outside-capture and later agent task ceilings
are distinct containments; neither is an assertion that native task exhaustion
has occurred.

| Site / step | Phase | Source file:line and producer → consumer | Pattern a–f / other | Will refuse / suspect | Why on the installed graph | Smallest fix | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — 44, brief 42; repeats at 68 | Outside capture bootstrap, after registration's allocation guard | `internal/v2/admin/capture_io_linux.go:335` → `internal/v2/admin/capture_io_linux.go:343` → **`internal/v2/admin/gate_args_linux.go:16`**; limit at `internal/v2/admin/resources_linux.go:225` | (c) | **Suspect** | The outside job inherits the parent's budget at `internal/v2/admin/capture_io_linux.go:277`; the default budget is 16 tasks at `scripts/v2-serve/bundle/main.go:252`. The fixed Go bootstrap starts after bwrap clears its environment. This argument builder supplies no `GOMAXPROCS`. Setting a later worker payload's environment cannot constrain the already-started bootstrap runtime. Actual CPU/runtime/thread counts are unmeasured. | Supply a trusted bounded `GOMAXPROCS` before the fixed Go bootstrap starts, then preserve the intended bound at final exec. Measure the actual task peak and `pids.events` under the installed unchanged budget; do not rely on a plain-root launch or an inherited setting. | serve2b |
| 2 — 44 → running/release; repeats at 68 | Outside producer lifetime | `internal/v2/service/reconcile_attempt.go:54` → `internal/v2/lifecycle/plan_capture.go:24` → **`internal/v2/admin/capture_io_linux.go:374`** → `internal/v2/admin/gate_linux.go:173` | (e), other: lifetime authority | **Suspect** | The capture worker expires with the original 30-second planning claim. Retries deliberately preserve that expiry at `internal/v2/lifecycle/plan_capture.go:36`. The helper turns it into the producer's kill timer, while the fixture agent has a 60-second wall budget at `scripts/v2-serve/bundle/main.go:252`. Producer failure then stops the agent at `internal/v2/admin/capture_io_linux.go:382`; clean EOF is required at `internal/v2/admin/capture_io_linux.go:100`. A slower start or proof/control sequence can therefore destroy still-needed capture. | Give the retained outside job its own bounded lifetime covering the run and authenticated drain. Keep current planning claims as mutation fences, preserve the same producer identity on retry, and retire it only through measured EOF/wait/drain. Do not simply renew an expired producer or lengthen an unrelated claim. | nb-r1/rr |
| 3 — 44; repeats at 68 | Projection binding before agent prepare | `internal/v2/service/agent_launch.go:163` → `internal/v2/assembly/projection.go:71` → `internal/v2/admin/credentials.go:123` → **`internal/v2/admin/credwire_linux.go:443`** | (f), other: missing native peer installation | **Will refuse** on the fresh default installation | Prepare reads the protected credential-peer catalog at `internal/v2/admin/credwire_linux.go:440` and returns `unavailable`, “protected native credential peers are not installed”, when absent. The installer's boot schema has no such input (`scripts/v2-admin/boot.py:632`); its publication loop installs helper/service units at `scripts/v2-admin/boot.py:832`, without this catalog or peer listeners. A checkout-wide production-source search found only consumers of the peer catalog, socket names and native protocol. The metadata endpoint at `internal / v2 / admin / credential_endpoint_linux.go:22` is a different listener. The prepare effect itself has a service owner. | Add the actual protected peer/catalog installation and native credential RPC owners, with measured executable, UID, containment and generation pins. The broker must have a distinct non-root UID outside the service and lane pool (`internal/v2/admin/credwire_linux.go:453`, `internal/v2/admin/credwire_linux.go:461`). Connect the existing metadata broker/identity to those real owners; do not seed receipts or write the catalog during a hardened runtime request. | new |
| 4 — 44, prepare retry; repeats at 68 | Expired agent prepare child escapes its parent stage | `internal/v2/service/agent_launch.go:154` → `internal/v2/service/agent_launch.go:262` → `internal/v2/store/read.go:578` → `internal/v2/service/reconcile.go:271` → **`internal/v2/admin/gate_control.go:54`** → `internal/v2/service/reconcile_attempt.go:173` | (d) | **Suspect**; refusal/fault is deterministic if this scheduling condition is reached | If a prepare attempt expires before bind, the child remains eligible in the outbox. Only retained materialization is intercepted before generic dispatch (`internal/v2/service/reconcile_attempt.go:43`). Generic reclaimed `HelperPrepare` sets `PreparedID` only for `bound`/`opened`; `spec_retained` leaves it empty, so reconciliation returns `invalid`, “incomplete retained gate reconciliation selector”. `HelperPrepare` is absent from both the terminal-planner and transient-attempt sets at `internal/v2/service/reconcile_attempt.go:163` and `internal/v2/service/reconcile_attempt.go:168`; that error faults and stops reconciliation. Parent-before-child ordering does not help if the parent defers before reclaiming its child. | Recognize this exact retained agent prepare child and route/defer it to its original parent stage before generic claiming/execution, including recovery/startup inventory. Reconcile the original helper attempt through that owner; retain unknown ownership and never invent a prepared ID. Preserve fatal handling of actual integrity/storage errors. | nb-agent |
| 5 — 44, then 45; repeats at 68/69 | Agent exec and fixture's installed CLI child | **`internal/v2/admin/gate_linux.go:581`** → `cmd/laneboss/serve-fixture/main.go:113` → `cmd/laneboss/serve-fixture/main.go:121`; budget at `scripts/v2-serve/bundle/main.go:252` | (c), (f) | **Suspect** | The agent payload omits `GOMAXPROCS`; the fixture starts a second Go executable inside the same agent containment for `identity.self`. Both runtimes and the containment supervisor consume the 16-task envelope, independently of site 1's outside cgroup. `InheritLaneCommand` preserves binding/socket descriptors at `internal/v2/client/inherit.go:25`; it does not reserve thread headroom. A successful native exec acknowledgement precedes the fixture's own CLI checks, so launch success alone cannot establish this phase passed. | Bound the trusted agent/fixture and child CLI runtimes and verify the combined peak under the real installed cgroup. Preserve the actual child exit/stderr and the running assertion at `scripts/v2-serve/lifecycle.py:112`; do not convert an exec acknowledgement or a short-lived fixture into a running result. | nb-agent |
| 6 — 44 after open, 45/46 while running; repeats at 68–70 | Periodic capture snapshot during a legitimate write | `internal/v2/service/launch_recovery.go:23` → `internal / v2 / admin / capture_reconcile_linux.go:71` → **`internal / v2 / admin / capture_reconcile_linux.go:91`**; writers at `internal/v2/admin/capture_io_linux.go:559` and `internal/v2/admin/capture_io_linux.go:495` | (d), other: snapshot consistency | **Suspect** | The one-second monitor freezes the producer at an arbitrary instruction, then reads spool files and marker. Production writes and syncs range bytes before updating the marker; marker replacement itself truncates before write. A freeze in either interval can yield “capture marker is incomplete or foreign” (`internal/v2/admin/capture_io_linux.go:592`) or “capture spool bytes differ from retained range digest” (`internal/v2/admin/capture_io_linux.go:606`) without a failed producer write. The error path kills producer and agent at `internal / v2 / admin / capture_reconcile_linux.go:57`, and recovery faults at `internal/v2/service/launch_recovery.go:37`. No native interleaving was measured here. | Establish a producer checkpoint or committed snapshot generation before freezing/reading. Defer only a recognized in-progress generation under the original owner; preserve actual failed-spool detection, exact digests and complete bytes. Exercise both a write-in-progress case and a genuine damaged-spool control under the shipped units. | serve2b |
| 7 — 48/49, stop → release; repeats at 72/73 | Capture monitor sees revoked lease before terminal capture pin | `internal/v2/admin/gate.go:349` → `internal/v2/admin/credstop.go:33` → `internal/v2/admin/launch_capture.go:246` → **`internal/v2/admin/launch_capture.go:252`** → `internal/v2/admin/journal.go:37`; terminal pin producer at `internal/v2/admin/arch_cap_linux.go:100` | (e), (d) | **Suspect** | Credential stop publishes `Revoked=true` before release drains capture. The read-only terminal shortcut requires an already retained `ArchiveObservation`; release produces it later. A monitor tick in that interval falls through to the active/unrevoked acquisition guard, returns “launch mutation requires a current active unrevoked lease”, records a capture failure and stops the recovery loop (`internal/v2/service/launch_recovery.go:79`, `internal/v2/service/launch_recovery.go:84`, `internal/v2/service/launch_recovery.go:37`). The terminal shortcut is implemented; the remaining question is this earlier transition window. | Route a correlated stopped/teardown-pending capture through its retained native read-only/EOF owner, and defer that explicit transition until the original drain can finish. Keep immediate revocation and all byte/EOF/receipt checks. Do not reactivate the lease or suppress unrelated containment failures. | nb-r1/rr |
| 8 — 51, after stop/quiescence/abandon; repeats at 75 | Archive lookup of the retained stopped allocation | `internal/v2/admin/gate.go:349` → `internal/v2/admin/credstop.go:33` → `internal/v2/admin/lease.go:441` → **`internal/v2/admin/arch_fs_linux.go:358`** | (e) | **Will refuse** after the fixture's successful credential-bearing explicit stop | Stop permanently sets the helper record's `Revoked` flag. Successful withdrawal and release preserve it; release retains storage for archive. `archiveParent` nevertheless rejects every revoked record with `containment_unknown`, “archive lost its current native storage owner”. Both fixture drivers use helper-mode credential profiles (`internal/v2/assembly/profiles_partial.go:59`), and the case explicitly stops them before archive (`scripts/v2-serve/lifecycle.py:238`). This is downstream of successful start/release, not evidence that stop itself failed. | Add a narrowly authorized archival/read-only disposition for the same stopped, withdrawn, measured allocation, checked against its actual release, end, run, boot and cancellation pins. Preserve the launch revocation and prohibition on writable reacquisition. Repair all archive-parent consumers, not only the first freeze call. | nb-a2 |
| 9 — 52/53; repeats at 76/77 | Fixture output makes the worktree dirty | `cmd/laneboss/serve-fixture/main.go:209` → `cmd/laneboss/serve-fixture/main.go:226` → `cmd/laneboss/serve-fixture/main.go:71` → `internal/v2/admin/clean_linux.go:311` → **`internal/v2/dataworker/cleanup.go:167`** | (f) | **Will refuse** clean completion once the fixture has run and archive is repaired | The fixture writes prompt, requests, CLI output and transcript into the worktree's `serve-state` directory. Cleanup explicitly includes untracked and ignored entries, then chooses `retain_dirty` at `internal/v2/admin/clean_linux.go:480`. The orchestrator returns `conflict`, “dirty workspace and branch remain retained”, rather than marking cleaned. The harness permits inspecting a retained dirty disposition (`scripts/v2-serve/run.py:308`), but it awaits a successful operation before that inspection (`scripts/v2-serve/lifecycle.py:174`); this cannot pass the scheduled collected row. | Put retained fixture diagnostics in its separately mounted history/evidence storage and update the fixture descriptor, request-file locations and evidence reader coherently (`internal/v2/assembly/fixture.go:208`). Keep real bytes and Git dirty detection; adding an ignore rule cannot solve the current ignored-file check. Do not force-remove, commit test output or claim retained work was collected. | serve2b |
| 10 — 68, before the repeated capture/open phases | Codex acquisition uses publication-time room evidence | `scripts/v2-serve/lifecycle.py:194` → `internal/v2/lifecycle/plan_runner.go:240` → `internal/v2/secrets/profiles.go:158` → **`internal/v2/secrets/profiles.go:135`**; producer at `internal/v2/admin/initial_profiles.go:59` | (f), other: observation lifetime | **Suspect** | Both profiles' authenticated observations are capped at five minutes during the initial publication. The loop performs all Claudock stop/archive/clean and another human ceremony before Codex acquisition. No fresh profile observation is produced in that loop. Crossing the window returns `forbidden`, “profile room evidence is stale or belongs to another enrolled login”. The current authenticator does provide real encrypted source read-back; the remaining issue is elapsed observation lifetime, not R8's absent material/room. | Retain a fresh authenticated observation through its actual protected producer before the second acquisition, or make the fixture's bounded execution meet the existing window and verify its timestamps. Never extend timestamps or availability with constants, replay initial publication as a refresh, or relax the five-minute validator. | serve2b |

Sites 7 and 8 share stop's retained revocation. Fixing the archival consumer
does not resolve a monitor tick before terminal capture is pinned. Site 9 is
a fixture placement defect; the collector's refusal preserves real dirty work.
The two Go ceiling sites require native task measurements and are not two
claims of a measured runtime crash.

## Agent open, running projection and first events

The R8 absent-driver findings are retired. The current scheduled chain is
`internal/v2/service/reconcile.go:184` →
`internal/v2/service/reconcile.go:188` →
`internal/v2/service/agent_launch.go:71` →
`internal/v2/service/agent_launch.go:75` →
`internal/v2/service/agent_launch.go:123` →
`internal/v2/service/agent_launch.go:127` →
`internal/v2/service/agent_launch.go:134` →
`internal/v2/service/agent_launch.go:137`.

The prepare child is real, retained and claimed. Bind atomically writes the
bound plan, lane, turn, endpoint and identity at
`internal/v2/service/agent_launch.go:342`. Its actual event producers are
`identity.bound` at `internal/v2/service/agent_launch.go:318` and
`lane.created` at `internal/v2/service/agent_launch.go:333`. After native
open/reconciliation, running state is written at
`internal/v2/service/agent_launch.go:372`, and `lane.started` is emitted in
the atomic opened publication at `internal/v2/service/agent_launch.go:386`
and `internal/v2/service/agent_launch.go:393`. These are implemented producers,
not a success inferred from `run.observed`.

Native open still validates the committed identity tuple
(`internal/v2/isolation/linux/control.go:224`), rechecks original plan and
handoff (`internal/v2/isolation/linux/service.go:215`), checks current
policy/grants/cancellation (`internal/v2/admin/open.go:85`,
`internal/v2/admin/open.go:118`), checks credentials
(`internal/v2/admin/open.go:140`) and holds the native broker guard
(`internal/v2/admin/credexec_linux.go:53`). The agent driver constructs its
permit tuple at `internal/v2/service/agent_launch.go:121`; the independent
checks above mean that the missing direct `Identity.BindLaunch` call alone
does not establish an authorization bypass. No security canary was run and no
security-gap fact is claimed.

Rows 45/69 call the actual status/check path
(`scripts/v2-serve/lifecycle.py:103`, `internal/v2/lifecycle/control.go:235`).
The helper measures positive running tasks at `internal/v2/admin/gate.go:271`;
retained completed-process observation is supplied at
`internal/v2/service/launch_control.go:299`. Rows 46/70 paginate real events
at `scripts/v2-serve/lifecycle.py:86` and require exact config/life/run,
service origin and positive sequence for all three events at
`scripts/v2-serve/lifecycle.py:233`. Preserve those assertions after sites
1–7; an exec receipt, other run's events or a projected label does not satisfy
them. A terminal early fixture exit remains observable, since the observation
validator accepts measured running or exited states
(`internal/v2/isolation/linux/control.go:178`); running publication is not
itself evidence that the fixture's first CLI call completed.

`readAgentObject` has a single-chunk bound at
`internal/v2/service/agent_launch.go:535`. Original request, prompt and
briefing bytes must fit that bound; the default bundle's actual serialized
sizes were not computed in this documents-only round. It is a conditional
size limitation, not an asserted next default-fixture failure.

## Input outside the numbered lifecycle catalog

Rows 43/67 select StartRequest files at `scripts/v2-serve/lifecycle.py:196`;
they do not execute interactive input. These two successive optional gates
must be built together if input is added. They do not add fictitious rows to
the 78-entry sequence or inflate the eight scheduled-site report.

| Step | Phase | Source file:line | Pattern a–f / other | Will refuse / suspect | Why | Smallest fix | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Off catalog — I1 | Live `lane.input` planning | `internal/v2/lifecycle/interactive.go:125` → **`internal/v2/lifecycle/input_worker.go:83`**; construction at `internal/v2/assembly/assembly.go:203` | (d) | **Will refuse if invoked** after normal live-run authorization | No InputControl is supplied by assembly, and no production store fallback implements its PlanInput / InputJob / InputChannel / WriteInput interface (`internal/v2/lifecycle/input_worker.go:17`). The result is `not_implemented`, “leased input channel worker control”. | Bind a real retained channel planner/writer with exact input/resize acknowledgement, current process generation and native reconciliation. Preserve original bytes and one-use write ownership. | new |
| Off catalog — I2 | Input outbox execution after I1 exists | `internal/v2/lifecycle/interactive.go:143` → **`internal/v2/service/host.go:319`** → `internal/v2/service/reconcile.go:328`; intended owner at `internal/v2/lifecycle/input_worker.go:172` | (d), (b) at the future native handoff | **Will refuse if only planning is added** | The emitted generic Worker has no installed route to ApplyInput. The service returns `not_implemented`, “effect execution requires its owning coordinator”. The plan grammar at `internal/v2/lifecycle/input_worker.go:144` does not include config, so its eventual native handoff must append the trusted config as the materialization/archive owners now do. There is no current spawned input child whose missing argument was measured. | Dispatch only the exact retained input job through its claimed owner and fixed native handoff; include trusted required CLI arguments at that boundary. Do not allow arbitrary Worker kinds or replace the real native write with a success receipt. | new |

## Stop, release, archive, clean and final collection

Rows 47/71 upload actual stop-reason bytes at
`scripts/v2-serve/lifecycle.py:121`. Rows 48/72 execute the committed Stop
effect through `internal/v2/service/reconcile.go:230`. Native stop kills and
waits, fences credentials and withdraws them at `internal/v2/admin/gate.go:348`.
`RecordStoppedRun` atomically produces the real end/release outbox entry
(`internal/v2/lifecycle/release.go:38`, `internal/v2/lifecycle/release.go:96`).
Rows 49/73 require an actual exit code or signal and zero survivors at
`scripts/v2-serve/lifecycle.py:135`; the next mutation rereads the advanced
generation at `scripts/v2-serve/lifecycle.py:144`.

Release has an owner: `internal/v2/service/reconcile.go:296` first calls
`DrainReleaseCaptures`, whose store commit and native acknowledgement occur
at `internal/v2/service/capture_drain.go:126` and
`internal/v2/service/capture_drain.go:133`. The helper must retain successful
producer wait and both EOFs (`internal/v2/admin/arch_cap_linux.go:77`), then
discharge the actual outside cgroup (`internal/v2/admin/capture_drain_linux.go:82`).
Native release independently measures connections/jobs/exports at
`internal/v2/admin/resources_linux.go:55`, compares them at
`internal/v2/admin/release.go:18`, retains storage at
`internal/v2/admin/lease.go:441`, and removes the agent cgroup at
`internal/v2/admin/lease.go:447`. A transient EOF/wait delay is already
deferred for HelperRelease at `internal/v2/service/reconcile_attempt.go:168`.
No absent release producer or absent drain-ack consumer is established here.
Sites 2, 6 and 7 can still prevent obtaining those required receipts.

Rows 50/74 request abandonment with an empty review
(`scripts/v2-serve/lifecycle.py:151`); they do not accept or merge real work.
Rows 51/75 reserve archive through `internal/v2/lifecycle/archive.go:53`.
After site 8, the implemented path is native freeze
(`internal/v2/admin/arch_fs_linux.go:381`), fixed archive worker
(`internal/v2/service/archive.go:33`), actual identity permit
(`internal/v2/service/archive.go:153`), and original worker retirement
(`internal/v2/service/archive_retire.go:53`) before completion
(`internal/v2/service/archive.go:212`). The archive owner is explicitly
recognized in `internal/v2/service/host.go:282`; its child has trusted config
at `internal/v2/admin/arch_gate_linux.go:92`. Archive retirement closes its
worker endpoint first (`internal/v2/service/archive_retire.go:50`) and keeps
unknown retirement pending through `internal/v2/service/archive_retire.go:80`.
These are present protocols requiring native evidence, not missing modules.

Rows 52/76 use the actual Clean owner at `internal/v2/service/host.go:291`.
The service runs the collector at `internal/v2/service/archive.go:252`,
independently verifies its retained receipt at
`internal/v2/service/archive.go:263`, and completes through
`internal/v2/service/archive.go:267`. Object collection precedes native
workspace removal (`internal/v2/dataworker/cleanup.go:122`,
`internal/v2/dataworker/cleanup.go:151`); the retained release and archive
must match at `internal/v2/admin/clean_linux.go:347`. The native collector
checks ancestry at `internal/v2/admin/clean_check_linux.go:28` and uses an
unforced removal at `internal/v2/admin/clean_linux.go:514`. Each destructive
call is bounded by its actual claim (`internal/v2/admin/clean_claim_linux.go:23`).
The default fixture creates no new commit, so unmerged-work refusal is not
asserted as its next barrier. Site 9's retained dirty work is sufficient to
block success. Rows 53/77 still require `cleaned=true` and an exact retained
`lane.cleaned` event (`scripts/v2-serve/lifecycle.py:178`,
`scripts/v2-serve/lifecycle.py:181`). Owners nb-g1 and nb-r1/rr must preserve
those independent collection gates.

Codex rows 54–67 repeat the human proofs, root grants/ticket and file selection
via `scripts/v2-serve/lifecycle.py:194` and
`scripts/v2-serve/lifecycle.py:208`; their exact driver is checked at
`scripts/v2-serve/lifecycle.py:204`. Row 68 uses a separate root and the same
installed prepare/open graph, with site 10's extra elapsed-time risk. Rows
69/70 repeat the native running/event assertions, and rows 71–77 repeat the
reason / stop / release / abandon / archive / clean / collected chain above. Both tagged
profiles select helper mode, so an unbound real Codex-file validator or
canonical Codex-file refresh is not an unconditional failure of this fixture
(`internal/v2/assembly/profiles_partial.go:59`,
`internal/v2/admin/credlife_linux.go:439`). Real-vendor acceptance remains
outside the fixture's claim.

At row 78, the harness collects both journals before named unit shutdown
(`scripts/v2-serve/run.py:1121`), stops the owned units at
`scripts/v2-serve/run.py:1130`, checks MainPID and successful service exit at
`scripts/v2-serve/run.py:1133` and `scripts/v2-serve/run.py:1137`, and requires
socket removal at `scripts/v2-serve/run.py:1152`. Host Close cancels workers,
closes connections and waits for their actual drain
(`internal/v2/service/host.go:240`, `internal/v2/service/host.go:252`,
`internal/v2/service/host.go:261`). A recorded reconciliation fault is joined
into Close at `internal/v2/service/host.go:272`, so sites 4/6/7 can also surface
as unsuccessful final service shutdown. The original failed row is preserved
at `scripts/v2-serve/run.py:1168`. Uncollected lane records remain cleanup
problems at `scripts/v2-serve/lifecycle.py:248` and
`scripts/v2-serve/lifecycle.py:261`; unit shutdown cannot make those records
collected. Deployment DrainDispatch is not this shutdown route.

## Installed hardening cross-check and retired findings

The shipped helper runs as root by the unit default; its ExecStart includes
config (`packaging/v2/linux/laneboss-helper.service.in:16`). It keeps UMask,
NoNewPrivileges and capability bounding at
`packaging/v2/linux/laneboss-helper.service.in:17`,
`packaging/v2/linux/laneboss-helper.service.in:18` and
`packaging/v2/linux/laneboss-helper.service.in:19`. ProtectSystem is strict
at `packaging/v2/linux/laneboss-helper.service.in:21`. Writable exceptions
are helper state/runtime, lane storage and cgroups at
`packaging/v2/linux/laneboss-helper.service.in:36`,
`packaging/v2/linux/laneboss-helper.service.in:37` and
`packaging/v2/linux/laneboss-helper.service.in:38`.

The service uses its dedicated UID at
`packaging/v2/linux/laneboss-service.service.in:11`, strict filesystem at
`packaging/v2/linux/laneboss-service.service.in:18`, protected cgroups at
`packaging/v2/linux/laneboss-service.service.in:25`, and namespace restrictions
at `packaging/v2/linux/laneboss-service.service.in:30`. Its writable state,
secret and runtime directories are at
`packaging/v2/linux/laneboss-service.service.in:32`. The helper template has
no explicit SystemCallFilter or RestrictNamespaces; neither template sets
TasksMax. The source-backed 16 limit is the fixture budget → `pids.max`, not
an observed effective unit TasksMax. No effective drop-ins or installed unit
properties were queried. Do not transfer the service's namespace restrictions
to a helper child merely because both use systemd.

Runtime writes inspected after capture registration are in the declared
writable trees: spool creation at `internal/v2/admin/capture_io_linux.go:388`,
credential metadata socket at `internal / v2 / admin / credential_endpoint_linux.go:16`,
lane/worker sockets at `internal/v2/service/lane_listener.go:55` and
`internal/v2/service/worker_listener.go:46`, and workspace registry publication
at `internal/v2/admin/workspace_linux.go:438`. The credential-peer `/etc`
access in site 3 is a read; an install-time owner must supply it. No remaining
runtime `/etc` mkdir/write on this traced path was established. Install-time
root publication at `scripts/v2-admin/boot.py:828` must not be mistaken for a
write executed within the hardened running helper.

The workspace registry explicitly root-chowns and Fchmods before publication
(`internal/v2/admin/workspace_linux.go:488`,
`internal/v2/admin/workspace_linux.go:491`), avoiding the old UMask mismatch.
Cleanup consumes the same path at `internal/v2/admin/clean_linux.go:28`, and
the harness independently reads the new helper-state location at
`scripts/v2-serve/run.py:278`. The old `/etc/workspaces` reader/writer mismatch
is not a current finding.

All traced actual CLI children now receive trusted config: fixed bootstrap
at `internal/v2/admin/gate_args_linux.go:38`, materialization at
`internal/v2/admin/worker_linux.go:191`, archive at
`internal/v2/admin/arch_gate_linux.go:92`, and fixture CLI at
`cmd/laneboss/serve-fixture/main.go:106`. The fixed bootstrap pre-parser
requires it before general CLI parsing
(`internal/v2/admin/bootstrap_entry_linux.go:22`). A names-only source search
finds `GOMAXPROCS` only in the materialization/archive payload builders;
the fixed bootstrap still precedes application of those payloads, as site 1
explains. No environment or process-command-line inspection was used.

Readiness does have producers: allocation activation saves active phase and
current boot at `internal/v2/admin/lease.go:298` and
`internal/v2/admin/lease.go:329`; storage initialization writes Ready after
inode/mode/sync checks at `internal/v2/admin/storage_linux.go:184` and saves
the record at `internal/v2/admin/launch_storage.go:174`. RegisterSpec rechecks
the same storage at `internal/v2/admin/spec.go:211`; prepare/open require it
at `internal/v2/admin/gate.go:54` and `internal/v2/admin/gate.go:140`. Carry
the actual parent journal through the serve2b prerequisite repair rather than
loosening each downstream guard. Stop intentionally changes authority:
sites 7–8 concern read-only consumers after that transition, not permission
to restore active launch authority.

R8's fixture room/material findings are also retired in this tagged graph.
The stand-in authenticator writes and fetches its actual encrypted material
at `internal/v2/assembly/profiles_partial.go:122` and
`internal/v2/assembly/profiles_partial.go:129`, computes availability from
exact read-back at `internal/v2/assembly/profiles_partial.go:134`, and publishes
that result at `internal/v2/admin/initial_profiles.go:64`. Site 10 concerns
its observation's age. Generic Worker refusal is not evidence that archive
or materialization lack owners: archive is explicit at
`internal/v2/service/host.go:282`, and materialization is intercepted at
`internal/v2/service/reconcile_attempt.go:43`. The separate optional input
owner is the actual missing branch.

## Retained evidence and limits

Only this document was authored in the checkout. No source/configuration,
generated rules, lane state or Git metadata was changed; no commit, test,
build, project-code interpreter run, native canary, agent session or cloud
operation was performed. No guard refusal occurred in R9. Source navigation
errors were not treated as product verification results.

The lane's external evidence directory retains `r9-input-brief.md`, the
pre-document `r9-source-files.txt` and `r9-source.tar`, native-peer search,
names-only GOMAXPROCS results, filtered unit excerpts, the final document,
citation list, citation/source-byte verification output and SHA-256 manifest.
The verification scope is local document references and retained source bytes.
There is no tested R9 binary or installed E2E result to report. Full installed
running/events, both drivers, native release/archive/clean and row 78 remain
acceptance work for the named owners after their preceding gates are repaired.
