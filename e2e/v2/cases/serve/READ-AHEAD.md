# Installed serve read-ahead, steps 43–78

Run 41 supersedes the historical row verdicts below with a complete current
[step 42–78 trace](READ-AHEAD-R41.md) on ce566a44. It records the runtime view,
stdin, abandonment-schema and namespace-family fixes, the five repaired catalog
anchors, the native-fixture scope correction, and exact observation/cleanup
composition findings for serve2b. The old R15 missing-bridge statement is no
longer current. All installed results remain pending Linux execution.

Run 38 note: green35 and green36 report only `mount_failed` at step 42; the
subsequent supplied systemd probes identify proc/EPERM and the independent
userns-sysctl/EROFS failure. The approved repair and both required lane landing
checks are described in [MOUNT-FAILURE.md](MOUNT-FAILURE.md). The historical R3
row below is superseded: the witness now matches the approved fresh subset=pid
shape and is checked on the creator thread, the sysctl options are removed,
seccomp retains nested namespace denial and lane procfs is remounted read-only.
Unit restrictions remain. Candidate installed acceptance is still pending.

Run 37 integration note: the working tree now combines serve2 `bec6bf14` with
lb-v2 `3bff4a3d`. The archive/store/cleanup, native retirement and real migration
modules described as separate dependencies below are present in the merged
source. R51/R52 are now installed runtime checks, rather than missing-module
claims. The archive worker has its native principal/client bridge; the
materialization projected-root bridge and agent endpoint projection under R15
still require their owning implementation. The row table below is the retained
run-36 read-ahead history, not a claim about run-37 E2E execution. No installed
E2E or authenticated model session has run in this authoring phase.

Run 36 uses the complete read-ahead table for `2b1e4ce4` against a checkout
based on `d6d3c36c`. “Implemented” means the source and deciding regressions
are present. Native canaries, red/candidate pairs and installed acceptance
remain pending disposable Linux execution. Nothing was runtime-tested on the
Mac. P2 (bwrap source resolution) and P3 (masked procfs visibility) remain
suspected installed failures until the actual canary/control pairs run.

The unit templates, native credential/cgroup constructor, resource limits,
syscall filter and run 35 creator/wait lifetime ownership are unchanged. The
helper uses and verifies the whole process's existing private unit mount
namespace, rather than unsharing one Go thread while leaving others behind.

| Original row | Verdict and deciding evidence required |
| --- | --- |
| 43 inputs | No change. Harness input/ticket checks; no helper gate runs. |
| 44 R1 | Preserved run 35. Actual primary exit owns creator-task release; readiness failure still gets bounded natural-exit collection before stop. No new attribution of the original SIGKILL is claimed. |
| 44 R2 | Implemented. Probe work and its regular read-denial fixture live under an exact `0710 root:<probe GID>` stage in the lanes tree. The sealed input is inherited through `/proc/self/fd/N`, never bound as a memfd. The `mount_source_unavailable` vocabulary already landed in run 35 and remains in `TestSetupCategories`. Run `TestPrivateStageGroup`, the actual bwrap descriptor canary and native memfd-bind control. |
| 44 R3 | Implemented; installed premise unproved. After its exclusive lock, the helper mounts a fresh read-only `subset=pid,nosuid,nodev,noexec` procfs under its runtime directory. It verifies a private mount namespace shared by all helper threads. The original masked `/proc` remains for helper observations; bwrap still creates its own PID namespace and mounts its own `/proc`. The lane canary checks procfs-relative `NSpid` mappings for self, PID 1 and every visible numeric process. `TestInstalledPristineProc` requires the original masked-proc invocation to reach `mount_failed`, then the identical invocation with the pristine mount to execute successfully. The ancestor-proc mutation must reach vendor exit 75, not a setup failure. |
| 44 R4 | Implemented. Bootstrap Landlock pins use the shared descriptor-relative no-link walk on EPERM/ENOSYS. Other errors stay refusals. Run the bootstrap route control in `TestRestrictedWalk`, then the installed isolation proof. |
| 44 R5 | Implemented. The canary verifies seals and exact input bytes on its inherited descriptor, compares a separate regular read-only projection, and uses that regular file for write denial and subsequent Landlock read denial. No memfd bind or sealed-file write error stands in for the path-denial measurements. Run `TestInstalledIsolationProof` and descriptor controls. |
| 44 R6 | Implemented. Both storage root and child opens use the shared walk. Exact owner/group/mode, named/opened inode and retained `os.Root` checks remain. Run both storage route controls, existing root/link regressions and installed allocation. |
| 44 R7 | Implemented. Data parents, tree reads and staged file creation use the same walk. `NO_XDEV` is preserved with mount IDs, including same-device bind mounts. Run data/tree route controls, `TestSharedWalk` and the actual private-namespace `TestWalkMountCrossing` pair. |
| 44 R8 | Implemented. The helper verifies the protected service binding and derives `workers` from `Dir(binding.Socket)`, matching the service. The chain requires root-owned `0755` ancestors and service-owned `0700` runtime/worker directories. The restricted-walk canary pins a real socket at a service-derived path different from helper runtime; its old-path control must fail. |
| 44 R9 | Implemented. The worker socket retains inode/type/service UID/GID/mode/link-count checks, uses the shared walk, and travels as an inherited `O_PATH` descriptor. The sandbox socket path points to `/proc/self/fd/N`. Only validated sealed inputs and the pinned socket lose CLOEXEC at vendor exec; other helper/control/mount descriptors remain closed. Run the actual bwrap socket-bind and descriptor-retention controls. Every service frame still needs native authentication. |
| 44 R10 | Implemented. Immutable sources move from helper `state/jobs` into `0710 root:<worker GID>` stages in the lanes tree; collection uses the same location. The quiescent lane's storage-parent group moves exclusively to the worker alongside destination ownership, then returns after actual read-back and ownership return. Parent mode/group checks cover each phase. No supplementary group or world traversal is added. Run group controls and full materialization/collection. |
| 44 R11 | Implemented. Agent storage parents are exactly `0710 root:<lane GID>`; the three lane-owned children stay `0700`. Allocation and independent collection require that exact parent. Existing fixtures now construct it explicitly. Run storage replacement/link regressions and installed agent launch. |
| 44 R12 | Implemented. Peer cgroup opens use the same held-root component walk and keep cgroup-v2 `Fstatfs` and device/inode checks. `TestCgroupRestricted` installs a real openat2 EPERM filter in a separate process and pins its actual cgroup. Run its route control and authenticated worker/lane frames. |
| 44 R13 | Covered by R3/R4. Capture's descriptor positions 6–10 are preserved; input/socket descriptors follow existing controls. Run the installed spool producer and authenticated EOF/drain path. |
| 45 R14 | Implemented. Running agent and worker observations read `pids.current` through the leased root. Missing, malformed, overflowed or zero live counts refuse observation; no constant fills `Survivors`. Terminal zero still requires independent quiescence. `TestRunningSurvivors` changes counter-file bytes; `TestLiveObservationSurvivors` exercises the helper response for a real retained blocked process. Run these controls and installed check/stop/collect. |
| 45 R15 | Deferred to the endpoint/worker composition owner. This checkout still lacks a lane client/binding projection, and `dataworker.RunInternal` retains the typed private native-principal/projected-root bridge barrier. A sealed binding and pinned socket do not implement that bridge. These remain precise launch barriers after setup. |
| 45 R16 | Deferred, possible only. Harness task budget remains 16. Measure the actual Go vendor plus child CLI before choosing a different harness budget. No limit is increased here. |
| 45–49 R17 | Deferred, possible only. Harness wall budget remains 60 seconds. Measure proof/launch/control duration before changing it. Native budget enforcement is preserved. |
| 46 events | No change. Store read; verify after actual launch. |
| 47 reason | No change. Service blob ceremony remains inside its existing writable paths. |
| 48 stop | R14 supplies live observations. Existing cgroup kill, bounded wait and UID-thread inventory remain. Actual native stop/quiescence is pending. |
| 49 quiescent, R18 | Implemented by R6 and the exact `0710` parent check in independent reference inventory. Source collection also reopens the new stage location through the shared walk. Actual collection remains pending. |
| 49 R19 | Deferred, suspected only. The existing scanner still refuses foreign nsfs descriptors. Replacing this needs retained lane namespace identities and a real unrelated-namespace control. Ignoring foreign handles would weaken collection. The next installed collection may stop here. |
| 50 abandon | No change. Store operation after measured termination. |
| 51 archive | Separate owner/integration dependency. The brief reports item 3 landed elsewhere. This checkout still has the typed lifecycle archive-reservation barrier and no service `ReserveArchive` implementer. No branch is merged here; verify the supervisor's integrated item 3 tree and archive read-back. |
| 52 clean | Separate owner/integration dependency. This checkout still has the `OwnedCollector` barrier and no grants `CollectOwned` implementer. Helper physical storage collection is distinct from the durable archive/branch receipt. Verify the integrated item 3 implementation. |
| 53 collected | No change. Read after actual collector receipt. |
| 54–66 human.codex.* | No change. Human peers skip lane containment resolution; ceremony proof/ticket/counter checks still apply. |
| 67 codex inputs | No change. Harness input checks. |
| 68–77 lane.codex.* | Same R1–R19 changes and deferrals. Collect the first lane and its capture/data jobs before measuring second-driver pool sufficiency. No pool expansion or authenticated-session claim. |
| 78 cleanup | Deferred runtime observation. Keep the existing 30-second unit drain and require actual successful service exit after lane collection. No timeout/kill policy relaxation. |

All 417 previous mutation IDs are retained. The catalog adds 26 controls and
re-anchors five existing controls to the extracted walk or its caller. Their
conditions and deciding tests remain. Controls still need Linux red-before-green
execution; compile failure, timeout, skip, wrong category or survival is incomplete
evidence. The procfs installed test also carries its own before/after native pair.

The first remaining composition barrier after setup is the private worker
bootstrap/root bridge in `internal/v2/dataworker/internal.go`. If its owner has
integrated that bridge, the next explicit agent barrier is the absent client/
binding projection (R15). R19 and archive/collector integration also need
resolution or measurement before a complete step-78 result can be claimed.

This phase retains `presence=simulated` and `human_approval=not_proven`.
The fixtures do not perform authenticated AI-service requests.
