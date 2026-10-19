# Installed serve handoff

The following handoff records the earlier fix-9 integration scope. The current
fix-12 administrator receiver candidate, proposed private peer protocol and
remaining broker/identity/store/worker requirements are documented in
[CREDENTIALS.md](CREDENTIALS.md). Its native and composed rows remain unexecuted;
this update supplies no installed serve or credential-delivery acceptance.

The fix-9 input/storage implementation and every remaining native gate are
listed in FIX9-STATUS.md. The complete administrator consumer row is still
unfinished. In particular, registered capture I/O, owned network/bootstrap
descriptors, prepared/opened gate control, private storage collection and native
release counters have no successful installed result. A refused capture is
explicit incomplete evidence; it is never a primary stream or review pass.

The installer now accepts paired optional launch_enrollment and
launch_enrollment_file boot fields. It retains the exact metadata next to the
installed runtime and passes the reference in the service installation.
Service/store must import those exact protected objects with private service
origin before source resolution. Uploaded manifest labels grant no enrollment
authority. Current planning/helper claims and original cancellation fences are
required before allocation, registration and control effects.

Acceptance for this round is only the installed CLI/socket serve case on the
composed Linux tree, with the matching base red run. Static checks and admin
unit/mutation cases are supporting evidence. No composed serve PASS is claimed.

## Request to lb-v2-serve

The inspected serve harness calls the old eight-argument installer, then starts
serve with setpriv outside the installed systemd unit. To exercise this slice:

1. Supply a protected file with schema laneboss.boot-input.v2 and call
   scripts/v2-admin/install.sh with --install, --config, --binary, --manifest,
   --boot and --evidence. The script README specifies every boot field. Inputs
   must retain actual runtime/bootstrap executable bytes, exact manifest hashes,
   a real private 32-byte native encryption key and measured Clef deployment,
   tokenizer and context pins. These are data/installed capabilities, not a
   human proof, lane identity, authenticated driver or model request. Do not
   insert an empty runtime, fake source hash, constant key or invented credential
   handle to make assembly construction succeed.
2. Run the same entry with --check --config NAME. It writes nothing: no evidence
   file, directory, lock, mode repair, account, unit or profile. Retain its stdout,
   stderr and actual exit outside the process. Require exit 0 and verified=true.
   The supporting boot_cli.py case also compares installed inode/mtime/hash/mode
   state across check/repeat and proves refusal of differing inputs/unsafe mode.
3. Start the installed helper and service units. The service unit now passes
   --installation /etc/laneboss-v2/service/NAME.json. A standalone setpriv serve
   process cannot issue privileged helper calls: the helper verifies the actual
   installed service cgroup and executable as well as its UID/GID. Do not weaken
   that check to fit the harness. The helper also requires its own unit and NNP.
4. Read the installed service UID/GID from the installation's matching admin
   binding or retained service.json, and pass the explicit installed binding to
   CLI calls. The human-class binding is discovery data, never human authority.
5. For state.authorized and later state operations, use the real kernel-bound
   lane/worker launch/enrollment path supplied by identity, Linux and lifecycle.
   Neither UID alone, forged Scope, label-only binding nor a fake WebAuthn proof
   is an authorized caller. Keep missing authorization as a failed check.
6. Run base/candidate on separate fresh boxes when their artifacts have one
   compiled version: the immutable binary destination is version keyed and a
   differing artifact is refused before creating accounts. Record the actual
   first base failure. The restriction-on base may first fail its old bare
   user-namespace control; an unsupported --boot or missing installed boot file
   is also an admin provisioning failure, never a missing-handler result.

Expected serve deltas: namespace.install and namespace.check use the real
capability-requiring unshare control; admin.install publishes the complete
protected boot bundle; installation sees the exact --installation unit argument,
root-owned boot/binding/runtime and service-owned private directories. serve and
health additionally require the other owners' constructors and service host.
All state.authorized / append / read / drop-reply / restart / retry / cardinality / changed-bytes
checks still require their real identity, transport, store and lifecycle ports.

## Runtime and native key enrollment

The installer retains the exact laneboss.runtime.v2 bytes under the immutable
release's runtime/CONFIG/manifest.json. Objects are copied from approved root IDs
and relative paths, verified by hash/size, then installed root-owned 0444/0555.
roots.json maps only enrolled IDs to those protected copies. The root-owned
boot catalog records the actual bytes and paths; RegisterSpec independently
verifies them. The runtime BlobRef is administrator-retained bootstrap data;
service/store must import/resolve that retained bootstrap object rather than
treat its ID as an arbitrary host path or invent a committed DB object.

The supplied native encryption key is installed only in the private secret
directory as keys/HANDLE.key (32 bytes, service UID/GID, 0600). HANDLE derives
from its actual SHA-256. keys/enrollment.json binds schema laneboss.native-key.v2,
algorithm aes-256-gcm, handle and relative key filename. Key bytes never enter
generic evidence, source, event, task or HOME files. The boot file carries only
the handle. lb-v2-secrets must consume this protected enrollment or supply its
reviewed native-key export/format before the composed native.New can pass.
This file provisioning is not a claimed working SecretBackend implementation.

The installed judge values enroll capabilities. Clef is the primary enrollment,
with the complete decided model name and measured deployment/tokenizer/context
pins; an explicit TypeSafe alternative needs its own real enrolled credential
handle. Policy generation still selects the active provider through approved
EffectivePolicy.Judge. Boot configuration never permits provider fallback or D6
policy changes. Consumers: assembly, judge, policy, service/store and packaging.

## Gate and descriptor handoff still open

RegisterSpec now reads original committed bytes from StateStore, checks metadata,
actual current grants/policy, raw/JCS digests and causal IDs, then registers them
over authenticated helper IPC. The helper checks its active life lease/resource
envelope and installed runtime pins before syncing its receipt. An unopened
allocation may be aborted with no process ID, generation, exit code or signal.
For an allocation that never reached Prepare, the private abort route requires
explicit empty prepared_id and spec_sha256 (or the actual registered spec digest
when registration succeeded). The journal must prove that no prepared/opened
phase exists. Integration should freeze this context-specific empty-ID exception
or supply a separate allocation-abort DTO; generic IDs otherwise remain nonempty.
Consumers are admin, lifecycle, Linux and service/store. No caller may invent a
prepared ID or process merely to collect a failed reservation.

The Linux lane's current CONTRACT-GAPS.md independently identifies the remaining
trusted descriptors and context missing from Launcher.Prepare/Launch/Stop/Abort/
Collect. Its BootstrapMain consumes a sealed descriptor protocol, but no reviewed
service-owned opened-runtime / materialization / credential / capture / gate handoff
reaches this administrator helper. Required consumers are lb-v2-linux,
lb-v2-identity, lifecycle, grants/dataworker, secrets, service/store and assembly.
Freeze the concrete fixed bootstrap invocation and descriptor ownership, capture
pipes and causal preparation/control resolver together. Do not execute repository
argv as root, serialize secrets into the public object store, invent a network
lease or open a gate based only on nonempty permit fields.

Prepare, OpenGate, ObserveGate, StopGate, ReconcileGate and ResolveRuntime remain
typed failing boundaries for that work. Identity owns BindLaunch and its actual
StateStore.LaunchBinding receipt check. The new Linux containment registry pins
an owned cgroup duplicate, boot/allocation/target/launch identity and actual peer
UID/GID, cgroup membership, pidfd and own process generation. It uses the existing
native boot-id:start-ticks convention; descendants use their own ticks. Register
only the exact helper ticket, and re-register/reconcile after a service restart.

Release is ported to ReleaseReceipt and validates measured facts, disagreement,
known-zero connection/job/export/survivor counts and exact replay. The production
resource observer currently returns containment_unknown because the fixed gate
wait status and connection/job/export owners are not connected. Empty cgroups
alone do not fill those missing facts. Service/store must commit the returned
measured receipt in EffectOutcome.Release and helper.released exactly once.
Never copy the comparison claim into a receipt to turn this gate green.

DeploymentInstaller methods remain unfinished and separate from lane leases.
Automatic removal of uncertain failed installations, live state or credentials
is also unavailable. Preserve their protected ownership/evidence and dispose
the authorized test box through the supervisor; no force-delete recovery exists.
