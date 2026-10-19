# Planning and helper refusal trace

Read ahead from `lifecycle.Service.PlanLaunch` in `launch_plan_stubs.go`
through each dependency and then through `Service.call`, the helper envelope,
and `leaseManager.dispatch`. A helper call is possible before agent preparation;
an early helper refusal therefore does not identify a prepare/open failure.

| Stage | Call path and helper methods | Checks retained at the boundary |
| --- | --- | --- |
| Source inputs | `planExecution.sourceInputs` → `ResolveLaunchSources` → `launchAuthority` → protected enrollment and committed object readback. Resume/turn/continue also reconcile the previous gate with `reconcile_gate`. | Explicit current planning claim, original request digest, reservation, cancellation epoch, grants, current policy, enrolled project/runtime and exact previous-life binding. |
| Allocation | `planExecution.allocate` journals the child `HelperAllocate` stage → `Service.Allocate` → `allocate_launch` → `allocateLaunch` → `allocate`/`activate` → storage creation. | Durable stage and cause, unchanged allocation policy, UID/GID availability, native UID/task inventory, cgroup ownership/limits/population, exact lease journal, protected storage identities. |
| Materialization | `planExecution.materialize` → the service-owned dataworker child stage. Its administrator port uses `data_open`, `data_selector`, `data_query`, `data_lease`, `data_register`, `data_prepare`, `data_gate`, `data_observe`, `data_native`, `data_measure`, `data_revoke` and `data_collect` as its job advances or recovers. | Separate child claim and worker principal; enrolled executable, confined process, data grants, canonical retained output, terminal zero-survivor observation and parent reservation fences. These are separate job stages, not one unconditional call list. |
| Runner plan | `planExecution.runnerPlan` → selected runner source/storage resolution → `ResolveLaunchSources` and `ResolveLaunchStorage` (`resolve_storage`). | Issued profile, protected source bytes, retained slot/session, explicit planning claim, exact allocated home/workspace/lease, replay and cancellation fences. |
| Capture | `planExecution.capture` → `RegisterCapture` (`register_capture`); replay uses `ReconcileCapture` (`reconcile_capture`). | Exact reserved worker/effect/cause, protected spool and original producer/pipe lifetime. A refused capture disposition still requires explicit policy validation. |
| Seal and replay | `verifyPlanned`, `verifyCapture`, `seal`, `recovery` retain and re-read the plan, spec and recovery handoff. | Original allocation receipt, measured data, source objects, prompt, capture and credential stages; no inferred replacement for a missing receipt. |
| Later registration and preparation | `RegisterSpec` (`register_spec`, then `runner_prompt`), `ResolveRuntime` (`resolve_runtime`, including registration readback), then helper preparation (`prepare`). | Validated registration/prepare cause, exact retained handoff/spec, runtime enrollment, native storage and executable checks, cancellation fences and the original gate lifetime. |

Every wire call also checks the installed service UID, protected installation,
root peer and fixed helper control-unit membership, request binding/nonce,
caller executable/privileges/lifetime, decode shape, operation result and reply
transport. Refused/closed requests produce a bounded `helper_request` record
with method, typed code and fixed check word. The private response transports
the same word; the service records it against the matching refusal through a
context observer so lifecycle normalization cannot erase it or confuse a later
failure with a recovered `not_found` query. The public error and scheduling
decision remain the original ones. Non-helper credential envelopes reject this
extra metadata, including empty values.

## Causes proved in this round

- Native zero-timeout pidfd polling and signal-zero checks can return `EINTR`
  under real `SIGURG` bursts. The real-kernel signal canary reproduced both
  peer-lifetime and gate-observation false refusals. Bounded retries now cover
  `pinnedPeer.alive`, `innerLifetime`, `Observe` and release lifetime; actual
  exit, invalid descriptors and retry exhaustion still refuse.
- Registration-stage `ResolveRuntime` previously called public source/storage
  resolvers without a planning claim, despite already holding a fully checked
  helper-register authority. The private shared resolvers now consume that
  authority and retain the original enrollment, grant, storage and fence checks.
  Public planning entry points still require their explicit planning claim.
- Withdrawal inventory could reject the journaled intermediate root-owned,
  lane-group `0700` state before the existing retry completed its group reset.
  Only journaled withdrawing/withdrawn/collecting records admit that state.
- Whole-file maps text limits allowed unrelated large mapping inventories to
  stop collection. Identity fields now stream with pathname chunks drained;
  malformed/read/cancellation failures still stop collection. Bootstrap also
  sets and rechecks an irreversible inherited `RLIMIT_NOFILE` ceiling of 1024.

The historical generic helper lines cannot prove which of these checks failed
on the installed run. The new journals are needed to attribute a recurrence.
Prepare/open/stop claimant comparisons and `currentStage` belong to the
separate planning review; this round adds diagnostic wrappers to `prepareGate`
and `launchAuthority` without changing their authority comparisons.

Installed canaries now derive the instance from their actual helper control
unit, use `loadInstallation`, and verify the versioned production release path.
The ordinary warm test process lacks that unit. Its prerequisite refusal is
retained as incomplete installed evidence; it is never converted into a skip,
a guessed instance, or a test-only helper path.

## Explicit attempts and source-cache recovery

Registration and runtime resolution consume the handoff authored by the
planning effect. `registrationLaunchAuthority` derives its planning selector
only from the caller's explicit `WithEffectLease` context and sends it through
the unchanged durable claim, reservation and cancellation checks. A missing,
stale or foreign attempt cannot discover and borrow a live claim. Both public
entry points are covered by the runtime authority regression.

`pinData` opens helper-state `sources`, its selected digest directory and `tree`
before opening lane workspace/home directories. The boot installer previously
created helper state without provisioning that cache. The installer now builds
it from the approved immutable project manifests and exact initial object
bytes, bounded before filesystem writes. Replaying the same installation can
provision an absent cache; an existing cache must match every path, kind, owner,
mode and byte. A changed cache is preserved and refused, never overwritten.

The root `TestDataOpenReservedRetry` reproduces `storage_directory` for an absent
cache while a TSYNC seccomp filter makes real `openat2` calls return `EPERM`.
The actual installer cache step then enables the native no-link opens, source
hash/readback and lane-to-worker ownership transfer. The helper resumes the
same journaled reservation and UID after checking the original operation,
monotonic attempt metadata, absent native stage and original agent storage.
An existing stage or later execution state retains its refusal. Successful
replays retain their original token and descriptors. The canary also checks
foreign/concurrent attempts, conflicting native stages, altered source bytes,
escaping paths, duplicate paths, symlink ancestors and exact cache replay.

That canary uses the component resource recorder at the cgroup boundary; its
filesystem, seccomp and durable journal observations are native evidence, not
proof of an installed helper unit or cgroup provisioning. The external store
review regressions run their unchanged assertions in real nonroot children
with empty isolated homes when the surrounding package runs as root.

## Retained fixed-worker launch handoff

The installed composition passes the real administrator client as identity's
`WorkerLaunchSource`. The materialization coordinator encloses identity's
borrow and the one-use worker open in `WithWorkerLaunch`. That private helper
conversation holds the canonical request gate, data allocation mutex and
original journal flock until it closes. Closing identity's borrowed guard
collects its descriptor duplicates; the coordinator still owns the enclosing
conversation through the actual native gate release.

`startDataGate` retains read-only views of the exact sealed input and endpoint
objects it projected. The helper transfers those objects and its original
bootstrap pidfd only to the authenticated installed service. Every guard check
re-authenticates the native bootstrap, journal, original descriptors, allocation
lock and current store binding/principal. Serializable labels never open a
replacement file or supply a process lifetime. Prepared containment reads are
available only within this same locked conversation; ordinary opened-peer
resolution keeps its consumed-gate requirement.

Identity permits the distinct outer bwrap and inner bootstrap lifetimes only
through that retained handoff. A worker spec's optional parent reservation is
checked against its actual sourced parent, data stage and complete causal
operation/request/target/cancellation pins. Unwired identity construction retains
the original owner-named `not_implemented` refusal.

The root handoff canary uses a disposable delegated helper unit and the actual
helper IPC handler, unprivileged client, confined native bootstrap, cgroups,
sealed descriptors, pidfds and allocation flock. Its service metadata is an
explicit fixture; it does not establish a complete installed service, successful
materialization or authenticated AI-service execution.

## Worker identity before agent preparation

The materialization worker's `identity.bound` precedes the agent's
`lane.created`. At this point the store retains a sourced reservation, child
claim, sealed input/spec and worker identity; it has not published an agent
lane. Identity must validate that reservation rather than require the future
target run's Lane projection. Start/adopt require an absent new life. Resume,
turn and continuation validate the previous run's existing life, exact base
generation, previous launch and cancellation epoch. The store's fresh
WorkerBinding checks independently retain the live reservation/epoch fence on
both permit-validation passes. Missing retained lives and changed boundaries
still refuse.

The worker identity event names its actual service claimant as writer. The
sealed handoff and child effect preserve the original service author. Identity
checks the event against the current child claimant without rewriting that
author or relaxing event ID, sequence, requester, request, operation or payload
checks. Agent identity events keep their separate original-author comparison.

`storedProjection` uses the same public absent-or-not-visible wording for a
missing lane as for other projections. Planning `not_found` journals now append
a fixed component, with closed store labels for objects, lanes, reservations,
launches, workers, materialization, grants, policy and source/template/guidance
projections. Other owners use the existing closed component fallback. Helper
check words remain attached. These labels contain no IDs or object values and
do not change public error JSON or absence/visibility behavior.

Failed-plan and cleanup readback compare their complete durable JSON values.
An in-process diagnostic component is deliberately absent after persistence;
it cannot trigger a false integrity failure or be persisted as new authority.
The original live refusal still carries its component to the effect journal.
Changed persisted error messages and cleanup issues continue to fail readback.
Owned-effect completion applies the same durable-value rule, so retaining a
diagnostic cannot halt unrelated effects after a correctly committed failure.
Its real-store canary requires exact public error-message changes to refuse.

`TestWorkerBindBeforeLaneCreated` reproduces the original `not_found` with a real
store-issued sourced reservation and worker identity event, then checks the
exact returned permit while the agent lane remains absent. Sealed memfds and
durable records are real Linux inputs; native peers, containment and helper
guards remain explicit component fixtures. `TestWorkerReservedLifeFence`
checks the retained-run boundaries, `TestWorkerEventWriter` distinguishes the
current claimant from the original author, and
`TestPlanningMissingComponentJournal` checks fixed labels and private-value
exclusion. These are component regressions, not installed E2E or authenticated
vendor-service acceptance.
