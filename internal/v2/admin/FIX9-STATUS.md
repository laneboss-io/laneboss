# Draft.4 fix 9 part 2 administrator status

This implementation starts at bda14f3 and
consumes Draft.4 fix 10. It remains an incomplete installed-launch row.
The helper now has a real native descriptor gate and retained control paths.
Only static checks are authorized on this Mac; no native, unit, red/green,
installed-service or authenticated vendor result is claimed.

A normal validated agent plan still cannot complete Prepare in this checkout:
the contract requires a real injected credential slot, and its protected native
projection owner is not implemented here. Endpoint projections and controlled
egress also retain explicit unsupported barriers. The low-level gate and its
real-process fixtures are implemented; this statement does not turn those
missing production handoffs into a launch pass.

## Per-method result

| Method | Implemented behavior | Remaining gate or refusal |
| --- | --- | --- |
| ResolveLaunchSources | Reads actual retained request/claim/reservation/grants/policy; preserves consumed authority references and compares level, role and driver pins. Human ticket/proof and retained authentic starter bindings are checked without manufacturing new authority. | Actual store authority consumption, D9/subset provenance and native consumer evidence remain required. |
| Allocate / ResolveLaunchStorage | Retains private work/home/history IDs and verifies actual owner/mode/device/inode under the installed helper root. Capture UID reservations also exclude those accounts from allocation. | Confined materialization and repeated-run spec/gate rollover remain incomplete. Missing, collecting or replaced storage refuses. |
| RegisterCapture | Rechecks the exact worker/reservation/current policy. An enrolled fixed supervisor creates one-use stdout/stderr pipes, a separate UID/cgroup and bounded private spool. Initial spool state syncs before readiness. Binding pins the actual bootstrap executable, pidfd/start generation and boot. Unsupported enrollment can produce the explicit D6-approved refusal only before any job attempt. | Authenticated outside-job upload/AppendCapture and drain acknowledgements are not implemented. Partial startup, integrity or ownership errors never become a refused fallback. |
| ReconcileCapture | Requires the original live producer, pipe owner, journal and boot. Freezes its actual cgroup, rechecks the executable/lifetime and hashes the retained spool before unfreezing. An incomplete snapshot/failure retains a separate marker and stops bounded work. | Lost helper ownership returns containment_unknown. It never re-registers pipes. Local EOF is not service EOF acknowledgement. Native freeze/read-back execution remains unrun. |
| RegisterSpec | Preserves original bytes/JCS digest and the complete agent plan, storage, capture and fix-10 binding facts. | Registration creates no process. Worker runtime/input/endpoint ownership remains on its separate unsupported handoff. |
| ResolveRuntime | Revalidates protected inventory and returns the original registered runtime/storage plus an actually created and retained offline network namespace. The child inherits that namespace before UID drop. | Nonempty network grants require the real forwarding owner. Lost namespace ownership refuses; it never creates a replacement on replay. The selected Linux launcher is still a stub in this checkout. |
| Prepare | Journals the attempt before process creation. The native implementation clones into the actual cgroup, drops UID/GID/groups, mounts pinned objects by descriptor, establishes namespaces/Landlock/seccomp and verifies native ready credentials, executable and lifetimes. The vendor waits on the helper-owned release pipe. | All mandatory credential, endpoint and fixed-worker projections still need their real owners. A normal agent plan therefore returns unsupported before vendor execution. Kernel/runtime fixture execution is pending. |
| OpenGate | Loads the actual committed LaunchBinding, full recovery/plan and current grants/policy/claim. Checks cancellation/CAS, Kind/role pins and current D6 exception. Syncs the exact opening/permit before writing the one-use descriptor token; syncs opened afterward. | A changed tuple, expired grants, second open or lost descriptor refuses. An uncertain opening requires reconciliation, never another release. |
| ObserveGate | Uses the original pidfd and actual containment supervisor wait status. Terminal zero survivors is recorded only after independent cgroup and every-UID-thread quiescence. | Lost wait ownership returns containment_unknown, even with old IDs or journal text. Process exit does not prove vendor/session interpretation or capture drain. |
| StopGate | Checks the current retained stop effect and exact handle; performs scoped cgroup.kill, waits for the original process and independently reobserves quiescence. | Unknown original ownership and stop/wait failures retain the lease. No UID-wide command-line matching is used. |
| ReconcileGate | Returns the same retained prepared/process/permit under exact lease/launch/prepared/operation pins. Same-helper service recovery uses that retained process. | Helper restart without descriptors/wait ownership and preparing/opening uncertainty return typed refusal. No reconciliation path launches a process. |
| AbortGate | Accepts the exact unopened prepared ID, proves no permit was consumed, closes/stops that gate and outside capture jobs, waits for native quiescence and collects only measured private ownership. Receipt has AgentExecuted=false and no invented process exit. | Opened/uncertain release cannot become abort. Registered capture without authenticated drain and lost native ownership prevent collection and UID reuse. |
| Release | Compares the caller claim with native wait/UID/cgroup facts, actual helper connection lifetime, outside-job registry and private descriptor/mount inventories. Syncs collection intent, performs rooted private storage collection and closes the owned namespace before kernel/UID release. | Its supported scope is the offline private gate, with no external endpoint/export/credential owners. Registered unacknowledged capture, a foreign held namespace, unreadable ownership, hard links or disagreement refuses. It does not invent service/foreign-worker counters. |

## Native contract and boundaries

Read GATE-NOTES.md for the fixed descriptor grammar, namespace projections,
scope of observations and installed fixture. The existing HelperControl
interfaces are used; no API/shared CLI/Linux source was edited. No generic root
argv/path endpoint, production fixture driver, shared credential home, host
network fallback or restart relaunch was introduced.

The gate journal is a comparison/ownership record, not a parallel service
authority store. Original request, identity, grants, D6 consumption and causal
effect authority remain with StateStore and its authentic installed service.
An exact identifier or helper receipt alone never supplies those authorities.

## Tests and proof still required

The catalog now has 77 rows: 72 Go and five namespace controls. Part 2 adds 23
Go controls. Each names its actual production guard, focused assertion and
deciding observation. The missing-spec control was adapted to the new refusal;
the removed storage-abort-only guard was replaced with a real hard-link control.

Real-process fixtures use the same production release/exec routine, actual
pipes, an executable canary, a native wait and an actual durable journal.
Spool fixtures use real random bytes, files, EOF, tampering, readiness and bounds.
Native restriction fixtures perform actual allowed/writable controls followed
by Landlock/seccomp attempts. These are source tests, not executed evidence here.
A test's stdin hold keeps an already-executed canary alive for observation; the
launch gate itself is the helper-owned descriptor.

The separate laneboss_gate_integration fixture requires an isolated installed
Linux configuration/unit/accounts/runtime and real delegated controllers.
Only its actual execution can establish the bwrap/cgroup/native bootstrap row.
The composed serve/agent/capture/recovery/release row, all reached red/green
assertions, full data/credential/endpoint provenance and independent review
remain necessary before acceptance. Aggregate disk quota and aggregate CPU
budget accounting also remain unresolved; the current native CPU limit is
per-process RLIMIT_CPU.

No Git add/commit, branch/worktree change, install, cloud operation, owner
message or model request was performed. Static commands, exact source/input
bytes, output/exits and archive hash read-back are retained in the lane's
external run-9 evidence. No tested project binary exists for this Mac phase.
The demo runner is not an authenticated AI-service test.
