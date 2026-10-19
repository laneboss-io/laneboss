# Bubblewrap compatibility and independent primary exit: run 34

Run 38 updates the current inventory below using the approved installed probe
results. The helper verifies a pristine procfs in the actual spawn namespace;
both builders omit sysctl-based userns disabling, retain nested-namespace
seccomp denials and remount lane procfs read-only. ProtectKernelTunables stays
enabled. See [MOUNT-FAILURE.md](MOUNT-FAILURE.md) for evidence and required
landing checks. The run-34 chronology below remains historical provenance.

Green32 on c8ee8dc5 returned to step 42. The retained gate refusal now says
child exit 1, bwrap_setup and option_unsupported before the fixed bootstrap
reports. The log records the category, not the literal option or vendor help.
The source inventory identifies --preserve-fds as the first incompatible
gate spelling for bubblewrap 0.9.0. Both builders also used fd-suffixed bind
spellings; this candidate replaces those with standard --bind/--ro-bind and
sources naming the exact inherited descriptor through /proc/self/fd/N.

The public reference target is the upstream
[v0.9.0 parser](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c).
The authoring host could not resolve the public source host, and no upstream
bytes or invented pinned help list are claimed. The independent regression
therefore uses the box's actual unprivileged --version and --help at test
time. Its exact public output is retained as base64 in the verbose transcript.
The mutation runner retains the actual bwrap binary bytes and hash for those
rows. A newer version's result does not qualify 0.9.0; green33 must retain the
box's actual 0.9.0 observations and must get past this option refusal.

## Complete production option inventory

This table inventories both final builders, before the command delimiter.
Each name and arity is checked against the actual vendor help on Linux.
Argument combinations and descriptor behavior also require the real canary;
a help match alone does not establish confinement.

| Option | Arguments and ordering | Admin gate | Isolation builder |
| --- | --- | --- | --- |
| --die-with-parent | none; retain parent-death behavior | yes | yes |
| --new-session | none; isolate the session/terminal relationship | yes | yes |
| --unshare-user | none; mandatory private user namespace | yes | yes |
| --unshare-pid | none; mandatory private PID namespace | yes | yes |
| --unshare-ipc | none; mandatory private IPC namespace | yes | yes |
| --unshare-uts | none; mandatory private UTS namespace | yes | yes |
| --unshare-net | none; mandatory unless already in the exact helper-owned empty netns | conditional on that owned descriptor | unconditional |
| --disable-userns | removed; incompatible with read-only kernel tunables | no | no |
| --assert-userns-disabled | removed with the sysctl-based option; seccomp enforces the property | no | no |
| --cap-drop | ALL; no cap-add or restored capability | yes | yes |
| --clearenv | none; selected sealed environment is installed by the bootstrap | yes | yes |
| --proc | /proc; private proc view associated with the private PID namespace | yes | yes |
| --dev | /dev; the limited device view | yes | yes |
| --dir | one destination; create parents before their children | work/home/run/runtime/job parents | home/run/work/data parents |
| --perms | 0700; immediately before its private tmpfs operation | yes | yes |
| --tmpfs | one destination; preserve private tmp/run/shm/home choices | tmp/run/lane/dev/shm | dev/shm/run plus unexported home/tmp |
| --ro-bind | /proc/self/fd/N and destination; N is the generated ExtraFiles slot | pinned read-only objects | pinned read-only objects |
| --bind | /proc/self/fd/N and destination; N is the generated ExtraFiles slot | pinned writable objects | pinned writable objects |
| --remount-ro | /proc and /; after private mounts, before command delimiter | yes | yes |
| --symlink | source spelling and destination; never a memfd/socket bind source | inherited sealed inputs and pinned socket | runtime links |
| --seccomp | 4; sealed filter descriptor, before command delimiter | installed by Go bootstrap instead | retained |
| --chdir | one sealed cwd; after mounts | installed by Go bootstrap instead | retained |
| -- | ends option parsing; later bootstrap --config is not a bwrap option | fixed bootstrap entry | pinned helper entry |

The removed --preserve-fds count was not an available 0.9.0 confinement
operation. ExtraFiles supplies the exact descriptor positions. The bootstrap
still requires sealed descriptor 3, the real release pipe, the outside control
peer, and the native credential/namespace proof. executePreparedGate marks
every remaining descriptor close-on-exec, consumes the exact closed release
token and closes the readiness route before the first vendor instruction.
The real bwrap descriptor canary verifies both inheritance and absence of the
exact extra-file inode after vendor exec; removing an option is not credited
as proof of those properties.

The old --bind-fd/--ro-bind-fd spellings are replaced in both builders. The
source remains a kernel reference to the already pinned object, not the
original host pathname. No mount target, descriptor numbering, read-only bit,
export grant or pinning validation changes. The existing actual mount probe
still checks inode identity, a real writable operation and EROFS without
Landlock masking a missing read-only mount.

Neither builder uses --cap-add, --uid, --gid, --userns, --userns2 or --pidns.
The root helper still selects the lane UID/GID, empty supplementary groups and
pinned cgroup during native creation before the unprivileged bwrap exec.
The candidate does not run bwrap as root, setuid or with file capabilities.
Its runtime option tests also select a nonzero UID when their test parent is
root. Optional user-namespace forms remain refused.

## Where confinement is enforced

| Property | Enforcement retained by this candidate |
| --- | --- |
| User/PID/IPC/UTS/mount namespaces and session | Mandatory bwrap forms; the native readiness owner independently verifies private namespace identities. |
| Network isolation | Exact helper-owned empty netns entered before dropping credentials, or unconditional bwrap unshare-net when no such descriptor is supplied; no host-network fallback. |
| UID/GID, supplementary groups and cgroup | nativeGateAttributes retains its exact credential/cgroup contract; the verified locked launcher checks its mount view. Ready SCM credentials, cgroup membership and generation remain mandatory. |
| Mount pinning and access | Validated source descriptors and targets, standard bind forms through proc-fd references, private tmpfs permissions and final read-only procfs/root. |
| Capabilities | bwrap cap-drop ALL plus actual effective-capability-zero checks in both bootstraps; no added capability form. |
| No-new-privileges | confineBootstrap installs PR_SET_NO_NEW_PRIVS before confinement/readiness. The isolation bootstrap retains its privilege drop and measured NNP postcondition. |
| Seccomp | Admin bootstrap retains its TSYNC filter, architecture guard, namespace/mount/escape denials and clone restrictions. Isolation retains sealed filter FD 4 and its actual syscall canaries. |
| Filesystem restriction | Both existing Landlock enforcement paths and their rights remain unchanged. |
| Descriptor closure and one-use release | Sealed inputs, exact pipe token plus EOF, explicit control close and CloseRange(CLOEXEC) before vendor exec remain unchanged. |

## Primary exit and stderr drain

The suspected wait gap is that exec.Cmd.Wait reaps the primary and then waits
for its stderr copy. An inherited writer can keep that copy open. Previously
the native gate published its only terminal signal after the entire Wait,
so a primary exit did not get its own recorded observation. This is a source
finding; the installed security effect remains suspected until the real
descendant canary and deciding controls run.

The gate now pins a private duplicate of the actual primary pidfd and observes
its exit independently. It records the kernel exit event and observation time
while the copy can still be pending. A real reaped pidfd may return POLLIN
with POLLHUP; unexpected or unavailable observations remain typed refusals.
Only the actual cmd.Wait supplies the final ProcessState and exit code.
Release also refuses observed primary exit or drain uncertainty and performs
a fresh native pidfd poll before consuming its pipe. The latter closes the
interval in which the asynchronous watcher has not yet published the event.

A one-second window bounds acceptance and Stop after the observed primary
exit. Pending drain is never returned as running or successful completion.
An exceeded window returns containment_unknown and retains the capture and
lease. The timeout does not close the sink, cancel the copier, alter WaitDelay
or discard bytes. Forwarding continues through eventual real EOF, including
writes made after the refusal. A late EOF cannot erase the recorded refusal.
The capture producer's failure watcher now uses this bounded native Stop path
instead of waiting unconditionally for the copy-completion channel, so its
existing stop-on-producer-failure policy can act while capture is retained.

The drain window is an acceptance deadline, not a promise that an arbitrary
descendant will close its descriptor. An uncooperative writer remains owned
and uncollected until the containment owner completes its existing stop and
collection route. This retains output rather than treating timeout as EOF.

## Regressions and deciding controls

All runtime rows remain pending on the authorized Linux box. No test or
mutant overlay ran on the authoring Mac. Every preceding 373 control row is
preserved; eleven new rows bring the catalog to 384.

| Regression | Deciding controls and required failure |
| --- | --- |
| TestNativeBwrapOptions calls real unprivileged bwrap version/help and checks both native-network branches of the production builder against that independent grammar. | native-bwrap-option restores preserve-fds and must fail the unadvertised-option assertion. native-bwrap-privilege adds cap-add and must fail the privileged-form assertion, even when help advertises that name. |
| TestBwrapAdvertisedOptions checks the separate isolation builder, including symlink, seccomp, cwd and both mount modes, against real unprivileged help. | isolation-bwrap-option inserts preserve-fds and must fail its unadvertised-option assertion. |
| TestNativeBwrapDescriptorInheritance executes the real unprivileged bwrap builder, checks actual sealed/pipe/socket/extra-file inputs, then calls executePreparedGate and observes the exact extra-file inode absent after real vendor exec. It claims no installed service or containment receipt. | native-bwrap-inherited shifts the inherited grammar and must fail the real canary. native-bwrap-cloexec leaves descriptor 6 outside CloseRange and must fail the vendor's actual inode-leak check. Both rows use the exact integration build tag. |
| TestNativeStderrDrain/accepted starts a real primary and its real descendant. The primary exits 17 while the descendant holds stderr. The pidfd event must be recorded before EOF, production Release must refuse without consuming the real pipe, and the fixture's separate release within the window must retain the entire randomized stream and real wait status. | native-primary-independent makes the watcher wait for copy completion and must fail the primary-exit-before-EOF assertion. native-primary-release bypasses the actual lifetime guard, consumes that pipe and must fail the ended-primary release assertion. |
| TestNativeStderrDrain/refused holds that real descendant past the window, requires a bounded typed refusal, then releases it to write the remaining large randomized stream. Every byte must still arrive, and late EOF must retain the refusal. | native-drain-refusal removes the deadline refusal; native-drain-stop-bound removes Stop's deadline signal. Both must fail bounded retained refusal. native-drain-retain closes the sink at timeout and must fail actual late-byte capture. |
| TestNativeStderrDrainInvalid supplies an actual invalid descriptor and requires refusal without acquiring an owner or child. | native-primary-invalid admits the failed duplicate and must fail the invalid-pin assertion. |

The runner permits only one new exact source exception, the isolation layout
builder, and its exact focused package. It allows only the named integration
tag for the two descriptor rows and only bwrap as the new native binary input.
Those two rows build a static test executable with CGO_ENABLED=0 and
buildmode=exe, retaining the explicit environment override with the command.
The canary independently rejects an ELF PT_INTERP entry, so an unmounted
dynamic loader cannot masquerade as a descriptor failure. A manual Linux
descriptor run needs the same static build and the integration tag.
Source roots and all prior mutation rows remain unchanged. A build error,
missing test, wrong failure, timeout or skipped test is not a killed control.

Green33 must retain the actual version/help/binary, all new red/candidate pairs
in ordinary and faults configurations, the integration descriptor canary and
the existing pinned mount behavior probes. It must pass the former option
refusal and continue through the unchanged native proof gates. Full installed
containment, audit and lifecycle qualification remains required. Presence is
simulated and human_approval=not_proven; no authenticated AI-service result is
claimed by these source or component checks.
