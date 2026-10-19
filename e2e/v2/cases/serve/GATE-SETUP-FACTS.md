# Native launch setup facts

The measured transient-unit bisect now identifies the full helper property
set's User/NoNewPrivileges interaction on lb-v2-capbisect1, systemd
255.4-1ubuntu8.17 / kernel 7.0.0-1014-aws. Fix 4d73e6ea removes explicit User
and uses the system manager's root default while retaining all hardening and
the existing bounding set. Run 30 adds real-template and startup refusal
regressions. See [the current capability-loss handoff](CAP-SETUID-LOSS.md) for
the measured scope, controls and next installed startup/gate contract.

The run-28 account below records the historical green26/green27 evidence
boundary before that bisect. Its missing-cause statements and proposed
diagnostic requests are superseded; the native confinement proof remains
required.

Run 28 starts at cf41d6ab. Green26 reports the administrator-owned
prerequisite_missing refusal with spawn errno=EPERM and clone3 size-zero=EINVAL
(argument validation reached). This establishes that the null/size-zero syscall
reached validation. It does not identify the original failing cmd.Start syscall
or prove that its valid CLONE_INTO_CGROUP request passed every kernel check.

## Evidence boundary

The complete named green26 log contains 524 lines and 71,309 bytes. Its SHA-256
is 8be79109d8fce9f0 (SHA-256 prefix).
The original error pair appears twice. The log contains no effective helper
RestrictNamespaces, SystemCallFilter, CapabilityBoundingSet, AmbientCapabilities,
NoNewPrivileges, Delegate, CapEff/CapBnd, seccomp, AppArmor-switch or cgroup-type
snapshot. Adjacent small files and the supplied archive were inspected without
printing runtime arguments/settings or identifiers. Related retained run files
also supplied no matching live snapshot. The snapshot path mentioned in the
brief was requested while independent source work continued.

Those green26 bytes alone could not select a live capability, delegation or
filter cause. The later bisect supplies the measured policy interaction and
fix. The retained failure facts continue to support diagnosis of any actual
later refusal without a separate successful collection command.

## Source findings

| Question | Current source |
| --- | --- |
| Is the helper delegated? | The helper template already declares Delegate=cpu memory pids and writable cgroup access. There is no missing Delegate directive in this source. |
| Is the target the helper's populated root? | binding.cgroupPath is the unit's lanes directory. setupCgroups moves the whole helper process into sibling control, enables the unit and lanes controllers, and Ensure creates a distinct lanes/ContainmentID leaf. Both limits on descendants are zero. startNativeGate opens that exact leaf for CLONE_INTO_CGROUP. |
| Are credential-drop capabilities missing from the template? | CapabilityBoundingSet already includes CAP_SETGID and CAP_SETUID. Root child setup clears supplementary groups, then sets GID and UID before exec. AmbientCapabilities is deliberately empty; ambient capabilities are not needed for the root helper's pre-exec drop and must not be passed to the lane. |
| Does source explicitly filter setup calls? | The helper has no explicit SystemCallFilter or RestrictNamespaces directive. The unprivileged service's separate namespace filter is not the helper's effective policy. Implicit hardening, live drop-ins, kernel and LSM state still need observation. |
| Is cgroup placement optional? | nativeGateAttributes still requires UseCgroupFD=true and the pinned leaf FD, with the same UID/GID and empty group list. There is no fork-then-migrate or unconfined fallback. |

Neither a new Delegate directive nor a wider capability set is justified by
these source facts. A zero-size syscall result also does not rule out later
kernel/LSM checks on the actual request. EPERM alone cannot select the missing
capability, credential syscall filter, cgroup policy or exec-stage LSM branch.

## Failure-only observations

Both launch paths now give the diagnostic the original SysProcAttr. The
no-network path locks its OS thread across Start and observation; the retained
network path already uses a locked thread. A failed start still returns the
original safe spawn errno and clone3 result with prerequisite_missing. Added
facts do not produce a success result or trigger another launch.

The helper reads its current-thread capabilities with capget, selecting PID
zero and capability ABI version three. Only effective CAP_SETUID, CAP_SETGID
and CAP_SYS_ADMIN present/absent verdicts are emitted. A denied/unavailable
read stays unavailable with a safe errno; permitted or bounding bits never
substitute for effective bits. No capability is changed.

Read-only prctl requests report NNP off/on and seccomp none/strict/filter.
Unknown or refused observations remain unknown/unavailable. This is actual
thread state, not proof that a particular setup syscall is allowed.

For an actual requested CgroupFD, fstat and fstatfs first distinguish an absent
descriptor, a regular file and a cgroup-v2 directory. Only after that check do
fixed descriptor-relative opens read cgroup.type, cgroup.subtree_control and
cgroup.procs. Reads are bounded to 4,096 bytes, require O_NOFOLLOW/O_CLOEXEC,
and close each owned descriptor. The caller's pinned descriptor stays open.
Only fixed domain kinds and empty/nonempty verdicts escape; process IDs,
controller names, paths, unknown file values and raw error text do not.

A separate O_WRONLY open of cgroup.procs, without O_TRUNC, O_CREAT or a write,
reports openable or a safe unavailable category. It closes immediately.
Openability does not prove a permitted attachment, a permitted write or common
ancestor migration authority. The failed launch stays failed regardless of
every observation. Failure of a diagnostic read never replaces the primary
spawn errno with a success or hides restoration failure.

The unit, installer, runtime mounts, cgroup allocation/setup, release gate,
credential constructor, namespace restoration, native lifetime ownership,
Landlock/seccomp and complete proof are unchanged. RestrictSUIDSGID=yes and
the exact previous capability bounding set remain. No kernel switch changes.

## Regressions

| Check | Deciding failure |
| --- | --- |
| TestNativeCapabilityFacts | The getter does not select the current thread/ABI, ignores effective bits, substitutes permitted bits, loses a refused observation or discloses wrapped private text. |
| TestNativeFactValues | Domain/population or NNP/seccomp verdicts are changed, arbitrary randomized file values appear, or a refused read becomes known state. |
| TestNativeCgroupFacts | An absent FD, real regular file or ordinary directory seeded with plausible control files impersonates a kernel cgroup. |
| TestNativeCgroupReads | Exact randomized file bytes are lost or changed, a real symlink is followed, a 4,097-byte control is admitted, or the caller's root descriptor closes. The actual opens/read/close operations are exercised on files, not credited as native cgroup evidence. |
| TestNativeThreadFacts | capget/prctl observations disagree with independent CapEff/NoNewPrivs/Seccomp fields read from the actual locked thread's procfs status. Raw status values are never printed. |
| TestHelperCapabilities | The current module's helper unit omits either existing credential-drop capability. The existing namespace/stop capability and unused-capability guards remain. |
| TestNativeSpawnMissing | A real missing executable does not carry the failure-only capability/thread/cgroup observation fields. |
| TestNativeSpawnCgroupFD | The real invalid FD failure does not inspect its original descriptor, or existing atomic placement/credential requirements are lost. |
| TestInstalledNativeSpawnRefusal | The actual retained-network branch under the installed fixture omits those fields, or any previous safe-failure/ownership gate fails. |
| TestInstalledIsolationProof | Any complete native namespace, cgroup, UID, runtime, syscall, network, input, readiness, lifetime or collection observation fails. |

The catalog retains 301 IDs, updates only the existing route anchor for its
signature, and adds 15, for 316. Each ordinary/faults reached-red/candidate
pair remains required on Linux. The installed-network diagnostic red omits
only the newly appended facts on that branch; its named setup-observation
assertion must fail before the candidate pass. The ordinary mutation runner
does not supply that integration tag or root fixture. No mutant was vetted or
executed on this Mac. No new regression has been credited as a runtime pass.

The candidate static matrix covers admin and all production/test importers:
Linux amd64/arm64 default, faults, partial/authenticator, combined, integration
and integration/faults; Darwin amd64/arm64 default and partial/authenticator.
It uses the shared Go cache, local toolchain, readonly modules and disabled
downloads. Exact commands, outputs, exits and source hashes are retained in
the run evidence. Static compilation/vetting does not prove the installed fix.
Both candidate static attempts passed all 16 configurations; the final attempt
includes randomized private-value fixtures. Formatting and diff checks passed.

The source files are spawn_facts_linux.go and its new tests,
native_spawn_linux.go (message assembly), network_linux.go (same-thread context),
the existing ordinary/installed spawn tests (required observation fields), and
review_linux_test.go (the two existing drop capabilities). The mutation catalog,
MUTATIONS.md, REQUESTS.md and GATE-CREATION.md carry the corresponding handoff.
No other production gate or service-owner source changes.

## Historical green27 evidence request

The request below preceded the capability bisect. The current required next
result is startup success and progress past lane.claudock.start, or the actual
next failure, as specified in CAP-SETUID-LOSS.md.

The next credential-free installed run must retain the matching unit bytes
and actual refusal, including these failure-path facts. Effective helper
systemctl properties and the original policy snapshot are still needed.
If the caps are present and the target is a domain leaf with empty subtree
and population, do not label those source branches broken from EPERM alone.

Capture the failing helper syscall with an outside observer on the authorized
disposable Linux machine. A strace selection should cover clone3/clone,
setgroups, setgid/setresgid, setuid/setresuid, execve, setns/unshare and the
later mount/pidfd/Landlock/seccomp calls. Use raw decoding for all selected
calls, retain the trace privately and publish only syscall names and errno
verdicts. Do not decode argv, settings, paths or mount payloads. Match the
observed call to its exact source/Go flags and keep the trace process's PID
for collection. A refused observation stops; it grants no unit bypass.

An observed cgroup defect requires a scoped leaf/delegation/permission repair.
An actually absent effective drop capability requires correcting exactly that
capability's root-helper setup. A setup-call filter or exec LSM denial requires
its exact policy correction. Do not add ambient capabilities to the lane,
remove a filter wholesale, skip group dropping or spawn outside the cgroup.

Software presence remains simulated and human_approval=not_proven. There is
no authenticated AI-service result. No local runtime test, project binary,
installed service, cloud operation, model request, commit or agent session
was run in that historical authoring session. The cause was later measured
and the explicit-User policy was fixed in 4d73e6ea; installed candidate
qualification remains separate.

Green27 should retain all current hardening and either reach the complete real
native proof after an evidenced narrow repair, or return the original EPERM
with actual capability/thread/cgroup verdicts and a matching private syscall
trace. No increased PASS count or particular policy cause is predicted from
the green26 bytes alone. The run-30 handoff replaces this historical forecast.
