# Gate child exit before readiness: run 32

Run 33 supersedes the stderr ownership and WaitDelay details below. Green31
first regressed at ordinary publication peer verification. The gate now owns
its capture duplicate through final drain, and new regressions cover real
ordinary peers and audit bytes continuing after readiness/caller close. See
[the current peer/audit handoff](PEER-AND-AUDIT.md) for evidence, cause limits,
controls and green32 requirements. This run-32 account remains historical.

Green30 on 3182e294 passes the stricter helper startup gate, then reports
read=eof, child exited code=1, observed wait, no bootstrap report and observed
child stop. This identifies a real early child exit, not its specific cause.
The candidate moves the Go reason route ahead of parsing and retains bounded
bwrap stderr categories for green31. No confinement or profile repair is
claimed without that next observation.

## Evidence and the AppArmor lead

The exact verify-3182e294-20261017-033913.log was read and retained from
~/.local / state / laneboss-top / evidence / lb-v2-serve2-green30-verify-evidence / .
It contains 526 lines and 72,405 bytes, SHA-256
fc42a389c3586633 (SHA-256 prefix).
The retained log includes namespace receipts with restriction=0,
baseline=unrestricted, profile_action=not_needed, ready=true and unchanged
switches. These are the recorded run's facts; Ubuntu's usual restriction=1
is not substituted for them. No sysctl was changed by this authoring run.

The shipped profile attaches exactly /usr/bin/bwrap and grants userns.
startNativeGate execs exactly /usr/bin/bwrap after its existing UID/GID/group
drop. scripts/v2-admin/namespace.sh --install invokes apparmor.sh when the
actual restriction is 1 and the exact profile/loaded state or unprivileged
probe is unavailable. The loader installs only the reviewed profile, reads
it back, reloads it and requires laneboss-bwrap (unconfined) in the kernel
registry. The namespace check repeats those byte/loaded checks and requires
a real unprivileged bwrap control while the copied unprofiled control refuses.
The harness runs both namespace modes before boot.py installs the service.
boot.py itself does not silently install or broaden an AppArmor profile.

probeAppArmor runs again before measureIsolation starts the gate. At actual
restriction=1 it requires the same protected profile bytes and loaded entry;
at 0 it explicitly does not require one. Thus the source attachment and
grant are correct, and a missing-profile defect has not been established by
the supplied run. No live box query was performed here. A future
namespace_denied stderr category is an observed error-text category, not
independent proof of which LSM or kernel policy refused the namespace.

## Exit paths and access inventory

| Stage before readiness | Access and possible failure | Observed exit convention / candidate route |
| --- | --- | --- |
| Initial child exec | Go sets the chosen nonroot UID/GID and empty groups before /usr/bin/bwrap. The regular root-owned distro executable must be executable, without set-id/file capabilities. A failed initial exec is returned by cmd.Start to the helper, before readiness. | Existing typed creation error; no invented child wait. |
| bwrap option parsing and native setup | bwrap parses the fixed flags, creates user/PID/IPC/UTS/mount state, preserves descriptors and binds pinned objects. It may refuse an unsupported option, namespace, UID/GID map, descriptor, mount or bootstrap exec. The AppArmor attachment is the same path it execs. | bwrap's own fatal setup exit is 1, before Go can install a route. The helper now retains its actual stderr category. |
| Bootstrap ELF/loader and Go runtime | The projected bootstrap is a pinned root-owned mode-0555 runtime file. Enrolled libraries are protected read/execute projections. Missing interpreter/libraries or Go runtime startup may fail before main. | Loader/exec conventions 126/127 and Go runtime/init convention 2 remain distinct from bwrap setup. Signals retain their real wait status. Stage labels are hints from exit conventions. |
| Package initialization | CLI feature init functions register method validators in memory; their registration errors panic. They do not read a selected configuration, binding or installation. A runtime/init fatality can precede main. | Normal Go fatal convention 2; no fabricated fixed reason when Go cannot run its route. |
| Original main and CLI prelude | The old main set signal handlers, then parsed internal helper --config NAME MODE. Parsing checked explicit config and the binding variable in memory. It did not read an installation or open a client socket for this internal method. Normal error mapping was 2/3/69/70/75, not 1. --install-release and --version branches were not selected by the fixed argv. | The new marker is handled before signal setup and ordinary parsing. Ordinary commands keep their existing dispatch. |
| First Go bootstrap setup | Descriptor 5 must already be an inherited seqpacket socket. It is duplicated with close-on-exec to a free descriptor at or above 6, without replacing worker/capture descriptors. | Failure to establish the route exits 80; a route-close failure uses 85. No configuration or file read precedes the pin. |
| Bootstrap arguments/config name | Only the two fixed modes and exact --config word shape are admitted. The config is checked in memory. No file path or external command can be selected by these arguments. | The pinned route reports entry.arguments / entry.config, with exits 81 / 82. |
| Descriptor 3 input | The helper supplied a sealed memfd, not a pathname. The child verifies seals/type/size, reads bounded exact bytes, closes it and strictly decodes. Inherited read authority survives the UID drop. | input.seals=100, input.read=101, input.decode=84. |
| Identity and control descriptors | The sealed UID/GID/mode/config/token, empty groups, socket peer, release pipe and empty effective capabilities remain mandatory. Descriptor 4 is the one-use read pipe; 5 is the readiness socket. | Individual fixed reasons have distinct exits 102-108. No root-account or installation read supplies an identity fallback. |
| Confinement and readiness | Dumpability/NNP/limits/Landlock/seccomp and chdir still precede the exact readiness send. The work mount is lane-owned mode 0700; runtime files are protected 0444/0555. /proc/thread-self/status is the child's own procfs state. | Distinct reasons/exits 109-125 cover executable input, cwd, readiness write and confinement. Parent proof gates are unchanged. |

The service installation, administrator binding and boot catalog are host
metadata; they are not opened by the descriptor bootstrap and are not added
to its mount view. Installer publication uses root-owned 0644 metadata where
declared, a 0600 boot catalog and private 0700 state owners; none is made
lane-readable as a fix. The helper has already supplied the actual sealed
data and pinned descriptors. No root-file read was found before the old reason
defer in this actual command path. The vendor/serve-fixture exit-1 paths start
only after readiness and release, so they cannot explain this closed gate.

## Route and stderr changes

The helper now selects the internal --fixed-bootstrap marker. The first main
statement dispatches it; RunContext also dispatches it before general parsing
for library callers. The first setup duplicates and checks descriptor 5, then
installs failure delivery before argument/config/input processing. The same
wrapper protects the legacy internal bootstrap adapter. It does not load an
installation or acquire root helper authority. The sealed identity and all
native checks still decide whether readiness can be sent.

Failures after the route use the existing closed reason vocabulary, extended
for entry and decode/context stages. Each reason has a unique nonzero exit;
unknown errors use 99. Codes 126/127 are reserved for external loader/exec
conventions. Later release/descriptor errors use 129-138 as declared in
bootstrap_entry.go. The helper reports the actual code and exit_stage_hint;
the hint interprets a code and does not prove that a particular syscall failed.
No token, config name, path, ID or raw error value is added to the diagnostic.

attachBootstrapStderr is shared by the actual gate and its socket regression.
It forwards exact stderr bytes to the existing private owner while retaining
at most 8192 pre-readiness bytes under a lock. The prefix freezes when the
start attempt returns, including before any vendor release. The public
bwrap_stderr field is one of namespace_denied, option_unsupported,
descriptor_or_path_unavailable, mount_failed, exec_failed,
identity_map_failed, other, none or unavailable. Arbitrary bytes remain private.
The ordinary three-second readiness deadline is unchanged. A separate
one-second exec WaitDelay bounds inherited stderr-pipe collection after child
exit; collection failure remains unavailable rather than successful wait.

## Regressions and deciding controls

The catalog retains 347 prior IDs, adapts bootstrap-reason-route to its actual
pinned-route caller and adds 15, for 362. Only cli.go is added as an exact
owned-file exception in the existing mutation runner. No main-package mutation
authority or broad new source root is granted.

| Regression | Required deciding red |
| --- | --- |
| TestBootstrapEntry/route-first | entry-route-first parses malformed argv before attempting its bad route. The actual child must exit 81 instead of required 80 and fail the distinct-exit assertion. |
| TestBootstrapEntry/route-stream | entry-route-type admits an actual stream socket instead of requiring seqpacket. The actual exit must cease to be 80 and fail the same assertion. |
| TestBootstrapEntry/mode and config | entry-mode / entry-config remove their respective checks. Actual invalid input reaches the later memfd refusal instead of 81 / 82; the distinct-exit assertion must fail. |
| TestBootstrapEntry/input | entry-stage-exit changes the real sealed-input stage to exit 1; the observed child exit must fail the 100 assertion. entry-report-after-drop breaks the actual pinned sender; the real unprivileged child's packet must disappear and fail the early-route assertion. |
| TestBootstrapStageCodes | bootstrap-stage-alias assigns two reasons the same exit. Complete coverage, uniqueness and reverse lookup must fail, including the unknown-stage fallback. |
| TestBootstrapPrelude | entry-cli-prelude removes the actual early dispatcher from RunContext. The re-executed CLI reaches ordinary parsing and must fail its required stage-100 exit. |
| TestNativeReadiness/bwrap | bootstrap-stderr-wire bypasses the actual shared stderr observer; a real child writes a randomized option message and exits 1, and the owned refusal must lose its category. bootstrap-wait-stage removes the bwrap stage hint and must fail the same deciding assertion. |
| TestBootstrapStderr/namespace and other | bootstrap-stderr-namespace replaces a known category, while bootstrap-stderr-private returns raw arbitrary input. Actual child-written bytes must fail the closed-category/privacy assertion. |
| TestBootstrapStderr/bound | bootstrap-stderr-bound widens retention to 16384. The actual large stream must fail its independent 8192-byte bound while exact forwarding remains required. |
| TestBootstrapStderr/empty | bootstrap-stderr-freeze disables freezing. A later real Write must change the retained prefix and fail the post-readiness assertion, while forwarding stays exact. |
| TestBootstrapStderrWriteError | bootstrap-stderr-forward-error swallows an actual closed destination's error. The real failed Write must fail its zero-byte/error assertion. |

Entry regressions re-execute the actual entry with real sockets and an
unprivileged credential. A root fixture performs the real UID/GID/group drop;
a nonroot fixture retains its own unprivileged identity. SCM credentials must
match that child. The CLI regression invokes actual RunContext, and stderr
regressions observe real child output, exact forwarding and actual exit 1.
These are component proofs of the diagnostic boundaries, not installed bwrap
namespace or confinement qualification. Require all ordinary/faults Linux
reached-red/candidate pairs and preserve the full installed native proof.

## Verification and next run

The candidate passed all 16 static vet configurations with the shared cache,
local toolchain, readonly modules and disabled downloads. Coverage includes
admin, CLI, main and all production/test importers on Linux amd64/arm64
default, faults, partial/authenticator, combined, integration and
integration/faults; Darwin amd64/arm64 default and partial/authenticator.
Formatting, diff checks and serve Python compilation passed. Mutation-runner
Python compilation is also required and retained in the final phase.

No runtime test, installed service, model request, new machine, new agent,
commit or merge ran on this Mac. The earlier unrelated private-folder search
was stopped; the supervisor explicitly authorized recovery with searches
limited to this checkout and the named lane evidence. That boundary is kept.

Green31 must retain bwrap_stderr, actual child wait and any fixed bootstrap
reason/stage. If the failure is namespace_denied, inspect the actual
restriction/profile state for that run before selecting a narrow repair.
If it is an option, descriptor, mount or loader/exec failure, repair exactly
that observed boundary. Never widen a file mode, skip/delay the UID drop,
change host restrictions, add capabilities or accept a weaker readiness proof.
The specific green30 cause remains unproven. Presence is simulated and
human_approval=not_proven; there is no authenticated AI-service result.
