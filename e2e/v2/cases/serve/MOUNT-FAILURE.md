# Installed procfs and nested user namespace boundary

The supplied systemd probe results establish two distinct failures with distro
bubblewrap 0.9.0 as a non-root UID under the helper's exact unit properties:

- The masked inherited procfs produces a proc mount refusal with `EPERM`.
  Removing only ProtectKernelTunables does not cure it, because other unit
  restrictions also overmount procfs paths.
- bwrap's `--disable-userns` attempts to open the user namespace sysctl for
  writing and fails with `EROFS` under read-only `/proc/sys`.
- Probe2 cases d and e succeed after a fresh procfs is mounted in the spawn
  namespace and the disabling/assertion options are omitted. The supplied
  follow-up identifies those as subset=pid and full-proc controls. The probe
  transcript records their actual return codes; the follow-up supplies the
  mount-option mapping.

Green35 and green36's original step-42 logs contain only the coarser
`mount_failed` refusal. Those logs alone did not identify the operation or
errno. The new probe evidence supports the approved run-38 repair; it is not
an installed acceptance result for this candidate.

## Approved repair

The helper mounts a fresh `subset=pid,nosuid,nodev,noexec` procfs, privately,
after acquiring its exclusive store lock. This matches the approved fresh
witness shape rather than run 36's read-only witness. Its `sys` subtree must
be absent. The original systemd-protected `/proc/sys` must still report
read-only. The helper never replaces the original proc mount or relaxes the
unit. Initial setup verifies a private namespace shared by all helper threads.
Spawn-time validation measures the actual creator, allowing separately isolated
credential-view workers to finish on their own retired threads.

Every production native spawn now verifies the witness on the locked creator
thread, after joining the retained network namespace and immediately before
Start. It checks the actual thread's mount namespace against the helper's,
rejects child mount-namespace clone/unshare flags, opens the pristine procfs,
checks its type/options and absent sys subtree, and finds the opened mount ID
at the exact expected root/path in that thread's bounded mount inventory.
Missing, foreign, malformed, duplicated or overmounted observations refuse
before creating the child. A failed preflight restores the retained network
thread before it can be reused; restoration failure retires the thread.

Both argv builders omit `--disable-userns` and `--assert-userns-disabled`.
They retain mandatory user/PID namespaces and `--proc /proc`, and explicitly
remount the lane's separate procfs read-only before vendor execution. Thus
the fresh helper witness has no writable kernel-tunable tree, the helper's
original kernel-tunable mount stays read-only, and the lane's full proc view
is read-only too. No writable host projection, shared mount, root/setuid
bwrap, capability grant or unit relaxation is added.

The fixed bootstrap retains the actual TSYNC seccomp deny program: all
unshare and setns calls return EPERM, clone with CLONE_NEWUSER or the other
existing namespace bits returns EPERM, and clone3 returns ENOSYS so ordinary
libc/runtime clone fallback remains available. Plain process/thread creation
stays allowed. Its filter construction is extracted for independent branch
tests without changing the instruction sequence. The isolation builder
already supplies the corresponding sealed deny program on descriptor 4.
Landlock, NNP, UID/groups/cgroup, closed readiness, release and lifetime gates
remain in place before the first vendor instruction.

## Landing regressions and controls

Run the candidate and all new catalog controls on disposable Linux in ordinary
and faults builds. There are thirty new controls: sixteen diagnose the actual
bounded stderr input, and fourteen cover argv compatibility, private read-only
lane procfs, the actual helper unit's kernel-tunable protection, seccomp
unshare/setns/clone/clone3 decisions, spawn verification/preflight and missing
or masked mount inventory. All prior IDs remain; only the moved isolation
option and network anchors are re-anchored. A compile error, timeout, skip,
wrong failure or surviving control is incomplete evidence.

`TestUsernsFilter` interprets the real bootstrap program
against forbidden and ordinary syscall inputs. `TestNativeSpawnPreflight`
executes a real child in the allowed case and requires no child in the
refused case, on the actual locked creator path. `TestNativeProcSpawnRefusal`
requires a closed containment refusal before clone3 for an unverified view.
The argv tests require both removal of the sysctl options and retention of
the private read-only proc mount.

Run the static `laneboss_gate_integration` fixture's
`TestInstalledPristineProc` as a separate process under the unchanged installed
root control unit. It requires the original proc/EPERM control, sets up
production pristine procfs, and measures actual credential/cgroup/netns
creation and mount-namespace inheritance. The wrong namespace must exit 78,
the non-proc descriptor must exit 79, and the actual pristine instance must
produce the randomized token and exit 0. It then uses the verified spawn
route for the identical real unprivileged bwrap invocation and private PID
view canary.

The same installed test has the two required lane landing checks. With fresh
procfs present, the real lane must report read-only `/proc/sys`, read the
actual current user-namespace limit, and receive EROFS from a write-open.
Unexpected writable access fails; its fallback write uses only the exact
existing value. No tunable value is printed. A nested stock bwrap, which
creates a user namespace without another proc mount or a sysctl write, must
succeed before the actual bootstrap seccomp. After that filter is installed,
unshare(CLONE_NEWUSER), unshare(0), user-namespace setns and the identical
nested bwrap must be refused. The nested bwrap must fail specifically at
namespace creation, not at an unrelated setup operation.

The lane canary's closed exit stages are 90 private view, 91 read-only mount,
92 tunable observation/error, 93 writable tunable, 94 nested positive control,
95 syscall positive controls, 96 seccomp installation, 97 syscall denials,
98 nested namespace denial and 99 output. Failure output retains only a
closed bwrap category and actual wait result. Namespace identities, mount IDs,
private runtime paths and raw stderr are never printed. The inherited
namespace/proc descriptors belong only to the separate inheritance canary
and never enter bwrap or the vendor.

`TestInstalledNativeClosedGate` and `TestInstalledIsolationProof` each acquire
exclusive helper ownership and perform production procfs setup before their
full native gates. These fixtures, all reached-red/candidate pairs and the
next complete installed green remain required. Mac candidate vet does not
establish either landing result. Keep `presence=simulated` and
`human_approval=not_proven`; these are credential-free fixture checks.

## Closed diagnostics

Readiness refusals retain the coarse bwrap category and add `bwrap_mount`
and `bwrap_errno`. Operations are proc, tmpfs, bind, ro-bind, remount, dev,
mqueue or other; none/unavailable distinguish a non-mount failure or absent
capture. Exact C-locale errno messages map into fixed errno names; unknown,
localized and truncated strings become other. Actual argv bind destination
and mode are matched privately to disambiguate read-only binds. Conflicting
modes become other. The same first recognized setup line decides every fact
under one capture lock. Exact private stderr forwarding, its 8192-byte bound,
freezing and full producer lifetime are retained.
