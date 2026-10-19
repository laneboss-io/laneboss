# Native gate creation diagnosis

The current cause and fix are in [CAP-SETUID-LOSS.md](CAP-SETUID-LOSS.md).
The full property bisect on lb-v2-capbisect1 identified the scoped
User/NoNewPrivileges interaction; 4d73e6ea uses default root with no User
directive. Run 30 adds the real-template and helper startup regressions.
The next installed run must pass startup and progress past lane.claudock.start
or report the actual next failure. The earlier diagnoses below are historical;
their missing-cause claims do not describe the current evidence.

Run 28 has the forwarded green26 errno pair: spawn EPERM, size-zero clone3
EINVAL. See [the current setup-facts handoff](GATE-SETUP-FACTS.md) for the
actual evidence scope, unchanged cgroup/capability source, added read-only
failure observations and green27 requirements. The run-27 account below
records the earlier evidence boundary.

Run 27 starts at ee4d08e7. The forwarded green25 result remains 42/78 PASS.
The native mount fallback passes with RestrictSUIDSGID=yes; the first reported
failure is lane.claudock.start, administrator-owned prerequisite_missing,
with the former generic creation message. Green24 reported that same creation
failure with the earlier relaxed SUID/SGID policy. This slice makes the next
refusal diagnosable; it does not claim an installed fix or a new native pass.

The entire retained green25 log was read in memory and retained byte for byte.
It contains two occurrences of the generic message and no errno, clone3 trace,
effective RestrictNamespaces / SystemCallFilter / CapabilityBoundingSet observation,
or AppArmor namespace-switch observation. An installed cause cannot be selected
from these bytes. No host policy is changed on speculation.

## Exact launch path

The G5 path is lane preflight, Linux Probe, service Probe, administrator
IsolationEvidence, measureIsolation, gateMounts, then startNativeGate.
After real cgroup/storage preparation and runtime descriptor pinning,
measureIsolation creates and retains a denied-network namespace with
unshare(CLONE_NEWNET). startInNetworkNamespace uses a locked helper thread to
join that exact namespace with setns(CLONE_NEWNET). Those operations already
have different failure messages. The observed message is emitted only when
the following cmd.Start fails, and only after successful thread restoration.

The constructor in gate_linux.go now delegates its unchanged SysProcAttr
literal to nativeGateAttributes. It sets the lane UID/GID, an explicit empty
supplementary group list, UseCgroupFD=true and the pinned target cgroup FD.
Cloneflags and Unshareflags remain zero. There is no fork-then-migrate path.

The inspected Go 1.26.5 syscall/exec_linux.go builds clone3 arguments when
UseCgroupFD is set. It adds CLONE_INTO_CGROUP to CLONE_VM and CLONE_VFORK and
passes the pinned cgroup FD. SIGCHLD is a separate exit_signal field. Go's
os/pidfd_linux.go can also add CLONE_PIDFD when native pidfds are available.
No CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWIPC, CLONE_NEWUTS,
CLONE_NEWNET, CLONE_NEWCGROUP or CLONE_NEWTIME is requested by this Go clone.

cmd.Start also covers child descriptor setup, chdir, setgroups, setgid,
setuid and execve of the fixed distro bwrap. Go returns child setup/exec
errno through its fork error pipe without the failed child's syscall name.
Consequently the old message does not establish that clone3 itself failed.
At that historical stage an AppArmor transition was one unselected hypothesis;
the later measured capability loss supplies the current policy diagnosis.

After a successful exec, bwrap creates its private user/mount/pid/ipc/uts
namespaces and either inherits the retained netns or creates one when none
was supplied. It mounts only the pinned projections. Later the fixed
bootstrap installs Landlock and seccomp, verifies its inputs, and attests
closed readiness. The explicit pidfd_open calls and every readiness, namespace,
cgroup, executable and lifetime check also have separate errors. They cannot
produce this particular pre-exec cmd.Start message.

## Narrow diagnostic change

Both creation paths now report only a fixed symbolic spawn errno, preserving
prerequisite_missing and the administrator owner. Nested PathError,
SyscallError and arbitrary wrapper text never enter the public message. Known
errors cover permission, availability, invalid flags/FDs, cgroup domain/support,
resource exhaustion, missing executable and descriptor exhaustion. Unknown
or non-errno errors report other without exposing their text.

Only after a failed Start, the helper invokes clone3 with a null argument
pointer and structure size zero. This is smaller than CLONE_ARGS_SIZE_VER0;
the kernel must refuse it before reading arguments or creating a task. No
valid namespace or process-creation request is used as a probe. In the retained
network path the probe runs on the same locked launch thread before restoration.
The original restoration/kill/reap priority remains in force.

The public observation is clone3 size-zero=EINVAL (argument validation reached),
ENOSYS, EPERM, EACCES or another fixed category. EINVAL establishes entry into
argument validation, not permission for CLONE_INTO_CGROUP or successful child
setup. ENOSYS alone cannot distinguish a missing kernel syscall from a filter
that returns ENOSYS. A denial is not proof that an AppArmor userns rule fired.
The probe never retries the launch or supplies a success result.

## Installed-policy investigation

The helper template has no RestrictNamespaces or explicit SystemCallFilter
directive. The separate unprivileged service does declare RestrictNamespaces;
it is not the root helper that calls Start. Effective helper settings,
drop-ins, inherited filters and actual capabilities were not present in the
forwarded log. Template inspection is not a measurement of that live state.

| Facility | Source facts and required installed observation |
| --- | --- |
| RestrictNamespaces | Inspect the effective helper property and any administrator drop-in. The Go clone requests no new namespace. Later bwrap requires user, mnt, pid, ipc, uts and net only; the helper's network operations require net. A namespace filter can also affect clone3 entry. Do not remove the restriction wholesale or infer the helper setting from the service unit. |
| SystemCallFilter | Inspect the effective helper property and the loaded systemd version, including filters implied by other hardening. Compare the failed spawn errno with the size-zero probe. A filtered clone3 is different from later bwrap unshare/mount or bootstrap seccomp. |
| CapabilityBoundingSet | The template retains CAP_SETUID and CAP_SETGID for child credentials, CAP_SYS_ADMIN for helper netns operations, and the existing cross-UID stop/read capabilities. Verify the live launch thread's effective and bounding sets; a template allowlist alone proves no capability is effective. Do not add CAP_NET_ADMIN or unrelated capabilities. |
| NoNewPrivileges | The template keeps yes and helper startup requires the actual flag to be one. It does not itself disable clone3. Credential syscalls still need their capabilities; executable LSM transitions can impose separate constraints. Preserve the flag and inspect the failing exec/audit result. |
| AppArmor userns | Keep kernel.apparmor_restrict_unprivileged_userns unchanged and retain the exact executable-only bwrap profile. AppArmor's userns denial normally occurs after exec when bwrap requests its userns, which produces a later gate error. A denied exec transition must be distinguished by the actual syscall/audit result. |
| Kernel/cgroup support | clone3 requires kernel support; CLONE_INTO_CGROUP requires cgroup v2 and kernel support for that flag. EACCES/EPERM can be cgroup permission policy, EBADF a bad FD, EBUSY a domain-controller conflict, and EOPNOTSUPP an unusable domain. EAGAIN/ENOMEM indicate resource constraints. None is identified by the old generic message. |

On the authorized disposable Ubuntu machine, retain the next typed failure and
the matching helper unit bytes. Capture only selected systemctl show properties
to private evidence: RestrictNamespaces, SystemCallFilter, CapabilityBoundingSet,
NoNewPrivileges, RestrictSUIDSGID, ProtectControlGroups and Delegate. Parse the
actual helper launch thread's CapEff, CapBnd, NoNewPrivs and Seccomp fields in
memory; publish only capability/property names and verdicts. Retain the current
kernel version and the namespace restriction values without modifying them.
No environment, ExecStart object, runtime argv or settings object is printed.

If the errno pair still does not identify the failed operation, trace the
existing helper by its verified main PID during the next credential-free
reproduction. Use strace raw decoding for every selected syscall so executable
paths, argument strings and mount data are not decoded. Select clone3, clone,
setns, unshare, setgroups, setgid, setuid, execve, mount, pidfd_open and the
Landlock/seccomp calls; retain the trace privately and emit only syscall names
and errno verdicts. Stop the tracer by its retained PID. Do not infer exact
flags from raw pointers; the constructor and matched Go source supply those.
A denied trace or missing tracer remains a stopped diagnostic step.

Only that observation can justify a narrowly scoped policy/capability/support
repair. No blanket unit relaxation, disabled userns restriction, changed kernel
setting, unconfined retry, cgroup bypass or fabricated containment is supplied
by this slice. There is no installer or sysctl change to reverse.

## Regressions and verification limits

| Test | Deciding failure |
| --- | --- |
| TestNativeSpawnDiagnostic | A wrapped errno loses its category/owner/code, a randomized private path/wrapper appears, or a denied/unknown probe is overstated as reached validation. |
| TestNativeClone3Probe | The injected syscall sees any nonzero argument/size, is not called exactly once, or its result is replaced. Injection covers diagnostic formatting only. |
| TestNativeSpawnMissing | A real missing randomized executable fails without the safe diagnostic, creates a registered process, or exposes its private name. |
| TestNativeSpawnCgroupFD | The production constructor loses atomic cgroup placement or group/UID/GID dropping, or a real invalid cgroup FD reaches later exec instead of refusing at clone3. A blocked entry retains its actual refusal category. |
| TestNativeSpawnSuccess | The reused real exact-byte canary does not produce the randomized output and successful native wait. It is a component spawn only. |
| TestNativeClone3Entry | The actual noncreating syscall does not return a supported refusal; zero cannot be accepted as a successful entry observation. |
| TestInstalledNativeSpawnRefusal | The real installed retained-network branch fails to reach the safe spawn refusal, masks restoration failure, registers a process with an invalid cgroup FD, or leaks private executable text. |
| TestInstalledIsolationProof | Any real runtime pin, namespace, cgroup, UID, readiness, Landlock, seccomp, network, input, limit, lifetime or collection check fails. |

Ten new controls retain all 291 existing IDs, for 301. Ordinary/faults reached
red/candidate runs and the installed-network red/candidate observation remain
pending authorized Linux execution. No test or mutation was executed on this
Mac. The installed-network red restores only that branch's former generic
error; it must reach its named diagnostic assertion before the candidate pass.

All 16 candidate-only static vet configurations passed using the shared cache,
local Go 1.26.5, readonly modules and disabled downloads. They cover the admin
package and all production/test importers for Linux amd64/arm64 with default,
faults, partial/authenticator, combined, integration and integration/faults;
Darwin amd64/arm64 with default and partial/authenticator. Formatting and diff
checks passed. These results compile/vet tests; they do not execute them.

The source change leaves the helper/service templates, installer, AppArmor
profile, namespace setup, native mount fallback, bootstrap and complete proof
unchanged. Cross-lane files are gate_linux.go (constructor delegation),
network_linux.go (both error paths), native_spawn_linux.go and its two test
files, the administrator mutation catalog/documentation, REQUESTS.md and this
handoff. The evidence retains the exact brief, source archives, Go launch
source, baseline log, command/output/exit records, hashes and manifest.

Software presence remains simulated, human_approval=not_proven. This is not an
authenticated AI-service test. No commit, service operation, cloud operation,
binary build, runtime test, model request or subagent was performed here.

Green26 should preserve RestrictSUIDSGID=yes and every real confinement gate,
then expose the original spawn errno and actual size-zero clone3 observation
if creation still refuses. The effective helper-policy/capability/kernel data
and, when needed, a value-free syscall trace should select the narrow repair.
No increase over 42/78, completed G5 proof or fixed installed cause is claimed
before that observation.
