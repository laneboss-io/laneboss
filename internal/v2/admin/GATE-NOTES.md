# Fixed prepared gate and capture ownership

This is administrator implementation documentation for the existing
HelperControl interface. FIX9-STATUS.md records the earlier per-method status;
[CREDENTIALS.md](CREDENTIALS.md) records the fix 12 receiver candidate and its
native counterpart handoff and remaining acceptance requirements.
Production credential, endpoint, worker, forwarding and authenticated capture
drain handoffs remain incomplete. Do not infer an installed launch pass from
these sources or a static compile.

## Review delta controls

The commit-scan follow-up centralizes acquisition in findActive/requireActive.
The readiness requirement rejects revoked leases, wrong boots, inactive phases,
missing or unready storage and storage already being collected. Allocation and
storage construction have an explicit initialization lifecycle: they still
require a current unrevoked allocation, and cannot demand storage that they
have not created yet. This lifecycle choice is private helper code, not an RPC
flag or a way to restore a revoked allocation.

| Lifecycle | Shared path |
| --- | --- |
| Spec, capture, gate, network and storage acquisition | findActive with ready storage; native capture/storage/network boundaries also call requireActive. |
| Data registration, preparation, opening and measurement | findData/openData through the same ready parent lookup. |
| Initial allocation and private storage construction | requireAllocation/findActive with storageInitializing, followed by journaled construction. |
| Observation, abort, release and collection | Their validated lifecycle paths; no new launch authority is granted. Collection still needs a completely valid journal. |
| Lane/data revocation and stopping | beginRecovery scopes validated owners and returns every retained problem through a typed error. |

Every helper-journal publication now passes through save. It constructs the
would-be complete record set and applies validateRecords and the canonical
identity inventory before calling the storage backend. This covers parent
allocation, stage reservation, worker opening, agent opening and later writes.
The identity inventory reports affected owners as well as conflicts, including
native UIDs and capture identities. An aliasing stage cannot poison the next
read by being saved under a parent identity.

Recovery inventories protected records without deleting malformed bytes. Normal
reads and writes refuse every reported problem. A stop or revocation may use
only independently validated records outside all identity, UID and containment
conflicts. Its writes freeze retained IDs and inputs and may only invalidate
jobs/leases or record a terminal gate observation. Recovery cannot acquire new
resources or collect/recycle unknown ownership. A bounded first typed error
contains the problem count, retained diagnostics and any selected-operation
failure, so the helper wire cannot hide damage by serializing another error
first. Unrecognized state-directory structure still refuses the inventory.

The added tests cover sibling-handler parity, a parent-alias stage rejected
before publication, malformed bytes retained during recovery, conflicting
owners refused, recovery authority/identity restoration refused and damage
visible in the serialized error. Lane/data/stop regressions reach explicit
failure boundaries with an unrelated invalid record; they do not fabricate a
successful native stop. The retained descriptor-gate fixture now constructs
real ready private directories before testing open. Linux red-before-green
and installed lifecycle observations remain required.

A successful producer wait with both durable pipe EOFs and a matching spool
read-back ends local capture production without killing the lane. Failure,
unknown wait, nonzero exit, missing EOF or changed spool bytes still stops it.
Clean terminal capture remains a queued outside job: EOF never supplies an
authenticated drain acknowledgement or permits UID recycling.

The data tree walker, stager and ownership return open every intermediate
parent with the full openat2 resolution restrictions. Syscalls without those
flags receive only a basename beneath that held parent. Symlink attributes
are read with llistxattr through the pinned parent and checked against the
same inode and ctime; flistxattr on O_PATH is unavailable on supported kernels.
The parent lane must be independently quiescent before result read-back and
before ownership can return to its UID.

Containment registration may pin a closed prepared gate. Peer resolution
requires its consumed opened gate and binds the endpoint class and worker
lease. It copies the registry ticket before the helper round trip and checks
the entry again before duplicating its descriptor and after native peer
verification. Revocation invalidates every matching lane/worker/stage entry,
including parent selectors. Lane revocation is durable before stopping the
lane and its outside jobs. Helper errors and unmatched selectors remain
errors; registry invalidation never manufactures a successful native stop.
Stops wait for the actual cgroup population event after the supervisor wait.

Collection inventories each thread's cwd/root, mapped device/inode pairs and
nsfs descriptors as well as open files and mounts. Every non-directory inode
must have one link. Worker lease IDs, launches, effects, stages, native lease
and containment IDs, tokens and principals remain unique across collected
records too. Native pool UIDs may be reused only after measured collection;
simultaneous worker UIDs still must differ.

### Helper capability rationale

CAP_SYS_ADMIN is required by newEmptyNetworkNamespace for CLONE_NEWNET and by
startInNetworkNamespace for setns into the retained initial-user-namespace
network namespace and restoration of the helper thread. The child drops all
capabilities before executing its confined payload.

CAP_KILL is required by nativeGate.Close's pidfd_send_signal and by the
network-restoration failure path's Process.Kill when the created process has
already dropped to a leased UID. Writing delegated cgroup.kill is a separate
file permission check and is not the reason to retain this capability.

CAP_NET_ADMIN has been removed. The supported offline path does not configure
interfaces, routes, netfilter or forwarding; controlled egress still refuses
without an enrolled owner. Installed namespace/stop acceptance under this
reduced unit remains required on disposable Linux.

## Gate construction and release

The private helper accepts only typed installed-service operations. Prepare
selects a registered exact spec and cause, validates private allocation and
quiescence, and persists preparing before any process is created. Unknown
attempts cannot be replaced by a new process.

The helper starts the fixed administrator artifact through the verified
unprivileged bwrap executable. clone enters the pinned cgroup with the leased
UID/GID and empty supplementary groups. bwrap makes the mount/user/PID/IPC/UTS
view private and drops all capabilities. A real denied-network namespace is
created and retained by the helper for offline grants; the launcher thread
joins it before dropping the child's UID, then restores its own namespace.
A restoration failure destroys the locked thread and refuses the attempt.

Only pinned runtime files and private allocation directories enter the mount
view. Source descriptors are consumed by bwrap; unused ends close before exec.
The fixed bootstrap checks its sealed descriptor, actual credentials, privilege
state and control descriptor types, then installs no-new-privileges, Landlock
ABI 3 or newer and the architecture-specific seccomp filter. The helper checks
SCM credentials, actual cgroup/namespaces, both native lifetimes and actual
bootstrap executable bytes before returning prepared.

The helper owns the only write end of the release pipe. The trusted bootstrap
blocks on that inherited descriptor before any vendor instruction. It requires
the exact random token followed by EOF, closes the control descriptors, marks
all remaining inherited descriptors CLOEXEC and replaces itself with the
enrolled executable. A missing owner, foreign token or extra byte refuses.
There is no sleep/polling flag that vendor code can bypass.

OpenGate compares the actual committed identity/plan/recovery/permit tuple and
fresh causal/grant/policy/cancellation fences. The helper syncs opening and the
exact consumed permit before the descriptor write. A second call conflicts.
A lost reply after opening is reconciled to that same retained lifetime.
Preparing/opening uncertainty or lost helper ownership refuses instead of
releasing again. Service restart can use the still-running helper owner;
helper restart currently gives the allowed typed containment_unknown route.

## Fixed internal entry and descriptor grammar

The only added internal helper mode words are prepared-gate and capture-spool,
each under one explicit installed configuration. They have no additional argv,
host path, URL or executable-selection grammar. Their data is a sealed inherited
descriptor constructed by the helper; bootstrap mode refuses a root/setid
invocation. Running an unprivileged copy grants no helper authority.

| Descriptor | Owner and meaning |
| --- | --- |
| 3 | Immutable sealed fixed bootstrap input. |
| 4 | Read end of the helper-owned one-use release pipe. |
| 5 | Private readiness socket; host SCM credentials identify the actual bootstrap PID. |
| 6/7 in capture mode | Only the helper-created stdout/stderr read ends. |
| 8/9 in capture mode | Private bounded spool files opened by the helper. |
| 10 in capture mode | Exact range/hash/pipe-EOF/failure marker. |

The agent receives only the corresponding write ends as stdout/stderr.
A caller cannot supply a descriptor or spool path through an RPC.

Runtime objects under usr/, lib/, lib64/, bin/ and etc/ssl/ retain those fixed
namespace-relative ABI paths. Other enrolled files map to /runtime/ID. The
bootstrap is fixed at /.laneboss-bootstrap. Private allocation roots map to
/work/main, /home/lane and /history; temporary views are private. The retained
runner argv must select its exact enrolled projection and /work/main cwd.
Currently only copy grants to the main private workspace are supported.

## Capture and acknowledgement

Registered capture uses another installed pool UID and cgroup outside the
agent UID and writable grants. The helper reserves that account in its journal
before process creation and verifies the actual fixed supervisor process.
It never reassigns a partial capture attempt to a fallback or another run.

The fixed producer first syncs its empty spool/range marker, then attests
readiness. It reads actual stdout/stderr pipes, writes and syncs exact bounded
ranges and digests, and records pipe EOF only after an actual zero-byte read.
The total unacknowledged spool is bounded by the smaller of 8 MiB and the
allocation's disk allowance. Full spool or I/O failure retains a marker/range
and stops bounded work. Process exit or a successful local write never supplies
an authenticated service receipt.

ReconcileCapture requires the original producer, pidfd/start generation, boot,
spool root and journal. It freezes that actual producer cgroup and waits for
the kernel's frozen event before hashing all retained bytes. It verifies the
executable again and resumes only after a complete matching read-back.
A mid-write snapshot can be incomplete; it then returns unknown, keeps the
source bytes/marker and a separate failure marker, and stops the run. It does
not relabel that result as complete capture.

The current checkout has no authenticated outside-job upload/AppendCapture
adapter. No append receipt, acknowledged offset, capture.closed event or
complete tool coverage is fabricated. Registered capture therefore blocks
final release/UID recycling until that integration exists. Refused capture
requires the exact current default-false D6 exception/approval and uses a
nonblocking /dev/null discard; it advertises no captured bytes.

## Observations and collection scope

Agent ProcessHandle generation identifies the actual containment supervisor
whose wait result the helper owns. The bootstrap child also has its own pinned
pidfd/start generation. CaptureBinding producer generation identifies the
actual fixed supervisor executable child. Neither generation is a caller label.

ObserveGate records terminal zero survivors only after the actual cgroup and
all host UID threads are empty. Release compares those native facts with the
service claim and refuses disagreement. It measures the helper-owned readiness
connection, outside jobs and private inode/fd/mount references. This scope is
limited to the supported offline private gate; unimplemented endpoint/export
or credential owners cannot acquire invented zero counters.

Collection retains a bounded inode inventory before removal, rejects unknown
hard links, cross-device trees, unreadable references and foreign retained
mount namespaces, then uses only rooted journaled allocation IDs. The namespace
descriptor and empty cgroup are collected after independent quiescence.
Failed collection retains ownership. Installed controls must include bind
mounts, detached descriptors/namespaces, helper loss and partial deletion.

Memory and PIDs use real cgroup controls. Wall expiry kills the retained cgroup;
CPU uses per-process RLIMIT_CPU. Aggregate CPU-seconds and disk-quota enforcement
are still required budget work. Repeated-run gate/spec rollover also remains
unfinished; a new process must never be substituted under an old binding.

## Linux fixture and remaining proof

Normal Linux tests cover actual descriptor wait/exec, wrong/extra/EOF releases,
one-use native and journal state, saved-opening interruption, retained/lost
ownership, current D6 policy, exact spool bytes and real kernel restriction
attempts. They contain no alternate vendor or successful fake native backend.

The installed test is separately tagged laneboss_gate_integration. Its
gate-integration configuration, accounts, matched immutable runtime/artifact,
bwrap profile and delegated unit/control cgroup must already exist on the
authorized disposable Linux box. Missing setup fails instead of skipping.
It observes an actual executable canary before/after release and the actual
kernel containment. Provisioning that fixture is separate authorized Linux
work and never changes a host switch from this Mac phase.

No native, unit, mutation or installed test ran in this static phase. Every
proposed guard control must reach its named assertion on a compiling mutant
before the unchanged candidate passes. Retain both binaries/bytes/hashes and
the complete output/exit/state evidence. Independent composed review and the
real D8/service/capture/release row remain required.
